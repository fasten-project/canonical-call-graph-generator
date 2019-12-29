#! /usr/bin/env python3
#
# Copyright (c) 2018-2020 FASTEN.
#
# This file is part of FASTEN
# (see https://www.fasten-project.eu/).
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

"""
Convert C call-graph edge list to FASTEN JSON Call-Graph Format.
Dependencies: https://www.debian.org/doc/debian-policy/ch-relationships.html
"""
import os
import re
import csv
import json
import logging
import argparse
import time
import subprocess as sp
from datetime import datetime


class CanonicalizationError(Exception):
    """Custom exception for Canonicalizers.
    """


def safe_split(string, sep=','):
    """Safe split using REGEX.

    Splits a string correctly with a separator when it has parenthesis and/or
    brackets using multiple negative lookahead.

    Args:
        string: A string to split into many strings.
        sep: The separator to use.

    Returns:
        A list of strings.

    Example:
        input: "foo, bar [foo, baz], baz (foo, bar)"
        returns: ["foo", "bar [foo, baz]", "baz (foo, bar)"]
    """
    regex = re.escape(sep) + r'\s*(?![^\[\]]*\])(?![^()]*\))'
    return re.split(regex, string)


def extract_text(inp, sep=('(', ')')):
    """Extract text from a string and return the input without the extracted
    string.

    Args:
        inp: The text from which the text is extracted
        sep: A tuple that contains the two separators.

    Returns:
        content: The string inside the separators.
        res: The input without the separators and their content.

    Example:
        input: "Hello (world)"
        returns: "world", "Hello"
    """
    if sep[0] in inp:
        lsep = inp.find(sep[0])
        rsep = inp.find(sep[1])
        content = inp[lsep+1:rsep]
        ret = "".join((inp[:lsep], inp[rsep+1:])).strip()
        return content, ret
    return '', inp


def parse_dependency(dep, forge):
    """Parse a dependency and return a dictionary in the FASTEN format.

    Args:
        dep: A string that contains a dependency. It may include alternatives
        dependencies (|), specific versions (inside parentheses), and specific
        architectures (inside brackets).

    Returns:
        A dict mappings values to the corresponding fields.
        A fasten dependency must contain forge-product, and may contain
        constraints and architectures (if they don't exist, it returns empty
        strings).
        In case of alternative dependencies it returns a list with the
        alternatives dependencies.

    Examples:
        1) input: "debhelper (>= 9)"
           return:
                {'architectures': '',
                 'constraints': '[9,)',
                 'forge': 'debian',
                 'product': 'debhelper'}

        2) input: "libdebian-installer4-dev [amd64] | libdebconfclient-dev"
           return:
                [{'architectures': 'amd64',
                  'constraints': '',
                  'forge': 'debian',
                  'product': 'libdebian-installer4-dev'},
                 {'architectures': '',
                  'constraints': '',
                  'forge': 'debian',
                  'product': 'libdebconfclient-dev'}]
    """
    if '|' in dep:
        return [parse_dependency(alt, forge) for alt in dep.split('|')]
    dep = dep.strip()
    name = ''
    version = ''
    arch = ''
    version, dep = extract_text(dep)
    arch, dep = extract_text(dep, ('[', ']'))
    name = dep.strip()
    return {'forge': forge, 'product': name,
            'constraints': use_mvn_spec(version), 'architectures': arch}


def get_product_names(dependencies):
    """Get product names from a list with dependencies"""
    names = set()
    for dep in dependencies:
        if isinstance(dep, dict):
            names.add(dep['product'])
        elif isinstance(dep, list):
            names.update([alt['product'] for alt in dep])
    return names


def find_nth(string, sub, nth):
    """Find index of nth substring in a string.

    Return:
        index of nth substring or -1.
    """
    if nth == 1:
        return string.find(sub)
    return string.find(sub, find_nth(string, sub, nth - 1) + 1)


def find_file(directory, extensions):
    """Find file with specific extension in a directory.

    Args:
        extensions: tuple with file extensions.

    Returns:
        The first file that satisfies the condition or -1 on failure.
    """
    for filename in os.listdir(directory):
        if filename.endswith(extensions):
            return "{}/{}".format(directory, filename)
    return None


def find_files(directory, extensions):
    """Find files with specific extensions in a directory.

    Args:
        extensions: tuple with file extensions.

    Returns:
        A list with files
    """
    res = set()
    for filename in os.listdir(directory):
        if filename.endswith(extensions):
            res.add("{}/{}".format(directory, filename))
    return list(res)


def find_product(path):
    """Find the corresponding product of a file.

    Args:
        The full path of a file.

    Returns:
        stdout, return status.
    """
    cmd = sp.Popen(['dpkg', '-S', path], stdout=sp.PIPE, stderr=sp.STDOUT)
    stdout, _ = cmd.communicate()
    status = cmd.returncode
    return stdout, status


def check_custom_deps(path, deps):
    """Find if the path match any of the regexes from deps

    Args:
        path: the path of a file.
        deps: a dict of dicts, the dicts must contain a key called regex which
            must contain a list with regexes.
    Returns:
        key of matched dependency or -1.

    Example:
        input:
            /usr/local/include/my_dep/utils.h,
            {
                "my_dep": {
                    "forge": "github",
                    "constraints": "",
                    "architecture": "",
                    "regex": [
                        "^/usr/local/include/my_dep/.*"
                    ]
                }
            }

    """
    for key, value in deps.items():
        for regex in value['regex']:
            if re.match(r'' + regex, path):
                return key
    return None


def use_mvn_spec(version):
    """Use Maven's version specification instead of Debian's.

    Debian packages use the syntax described here:
        https://www.debian.org/doc/debian-policy/ch-relationships.html
    Whereas Maven packages use the following specification:
        https://maven.apache.org/pom.html#Dependency_Version_Requirement_Specification

    FASTEN Canonicalized Call Graphs follows the Maven's specification.
    """
    if "<<" in version:
        return '(,{})'.format(version.replace('<<', '').strip())
    if "<=" in version:
        return '(,{}]'.format(version.replace('<=', '').strip())
    if ">>" in version:
        return '({},)'.format(version.replace('>>', '').strip())
    if ">=" in version:
        return '[{},)'.format(version.replace('>=', '').strip())
    if "=" in version:
        return '[{}]'.format(version.replace('=', '').strip())
    return version


def parse_changelog(filename):
    """Parse Debian syntax changelog files and return last date.

    Args:
        filename: filename of changelog
    Returns:
        date in the format day-of-week, dd month yyyy hh:mm:ss +zzzz or -1
    """
    with open(filename, 'r') as changelog:
        for line in changelog.readlines():
            if re.match(r'^ .*<.*@.*>  [A-Z][a-z][a-z], [0-9][0-9]', line):
                return re.split(r'^ .*<.*@.*>', line)[1].strip()


def parse_deb_file(filename):
    """Parse a .deb or .udeb file using dpkg -I

    Args:
        filename: filename of changelog

    Returns:
        dict: with the following keys; Package, Source, Version, Architecture,
            and Depends (not always)
    """
    cmd = sp.Popen(['dpkg', '-I', filename], stdout=sp.PIPE, stderr=sp.STDOUT)
    stdout, _ = cmd.communicate()
    # TODO handle errors
    # status = cmd.returncode
    res = {}
    for line in stdout.decode().split('\n'):
        line = line.strip()
        if line.startswith('Package:'):
            res['Package'] = line[line.find(':')+1:].strip()
        elif line.startswith('Source:'):
            res['Source'] = line[line.find(':')+1:].strip()
        elif line.startswith('Version:'):
            res['Version'] = line[line.find(':')+1:].strip()
        elif line.startswith('Architecture:'):
            res['Architecture'] = line[line.find(':')+1:].strip()
        elif line.startswith('Depends:'):
            res['Depends'] = line[line.find(':')+1:].strip()
    return res


def convert_debian_time_to_unix(debian_time):
    """Convert Debian time to unix time, i.e. seconds from epoch.

    Args:
         date in the format day-of-week, dd month yyyy hh:mm:ss +zzzz

    Returns:
        str of unix timestamp
    """
    dt_obj = datetime.strptime(debian_time, '%a, %d %b %Y %H:%M:%S %z')
    return str(int(time.mktime(dt_obj.timetuple())))


def canonicalize_path(path):
    """Canonicalize a given path.

    If the path starts with /build/XXX/package-version then remove this prefix.

    Args:
        path

    Returns:
        Canonicalized path.
    """
    dummy_prefix = '/build/dummy_pkg/pkg-version/'
    if not path.startswith('/'):
        path = dummy_prefix + path
    path = os.path.abspath(path)
    # Remove /build prefix
    prefix_regex = re.match(r'(/build/[^/]*/[^/]*-[^/]*/)(.*)', path)
    if prefix_regex:
        path = prefix_regex.groups()[1]
    return path


class C_Canonicalizer:
    """A canonicalizer that transforms C Call-Graphs to FASTEN Call-Graphs

    You should always run this tool in the environment where the Call-Graph
    produced. The format of the input must be edge list separated by space.

    **Currently it only supports Debian Packages**

    To use:
        can = C_Canonicalizer('directory')
        can.canonicalize()
    """
    def __init__(self, directory, forge="debian", console_logging=True,
                 file_logging=False, logging_level='DEBUG', custom_deps=None,
                 product_regex=None, output=None):
        """C_Canonicalizer constructor.

        Args:
            directory: A directory that must contains, an .deb
                or .udeb file, an .txt file with the edge list produced
                by the analysis.
            forge: The forge of the analyzed package.
            console_logging: Enable logs to appear in stdout.
            file_logging: Create a file called debug.log in the 'directory'
                with the logs.
            custom_deps: User defined dependencies and constraints
            product_regex: Regex to match products files
            output: File to save the canonicalized call graph
        Attributes:
            directory: directory path with analysis results.
            cgraph: Call-Graph filename.
            deb: deb or udeb filename.
            changelog: changelog file.
            forge: Product's forge.
            product: Product's name.
            source: Source's name.
            version: Product's version (string).
            version: Product's architecture.
            timestamp: seconds form epoch.
            dependencies: Product's dependencies (dict or list).
            can_graph: Canonicalized Call-Graph.
            orphan_deps: Dependencies that are not declared in deb.
        Raise:
            CanonicalizationError: if .txt or .deb files not found.
        """
        self._set_logger(console_logging, file_logging, logging_level)

        self.directory = directory

        self.cgraph = find_file(self.directory, '.txt')
        if self.cgraph is None:
            raise CanonicalizationError(".txt file not found")
        self.deb = find_file(self.directory, ('.deb', '.udeb'))
        if self.deb is None:
            raise CanonicalizationError(".deb or .udeb file not found")
        self.changelog = find_file(self.directory, ('changelog'))
        if self.changelog is None:
            raise CanonicalizationError("changelog file not found")

        self.forge = forge
        self.product = None
        self.source = None
        self.version = None
        self.architecture = None
        self.timestamp = None
        self.can_graph = []

        # Nodes that contain one of those values are skipped from the canonical
        # Call-Graph
        self.rules = ['UNDEF']

        self.dependencies = []
        # dict of dicts
        self.custom_deps = None
        if custom_deps is not None:
            with open(custom_deps, 'r') as fdr:
                self.custom_deps = json.load(fdr)
            for key, value in self.custom_deps.items():
                if value['keep']:
                    self.dependencies.append({
                        "forge": value['forge'],
                        "product": key,
                        "constraints": use_mvn_spec(value['constraints']),
                        "architecture": value['architecture']
                    })
                else:
                    self.rules.append(key)

        self.product_regex = product_regex
        if self.product_regex is None:
            # Default regex to detect files when analyzing a product in sbuild
            # environment.
            self.product_regex = '^/build/[^/]*/.*$'

        self.output = output
        if self.output is None:
            self.output = self.directory + '/can_cgraph.json'

        self.orphan_deps = set()

    def parse_files(self):
        # deb file
        dpkg = parse_deb_file(self.deb)
        self.product = dpkg['Package']
        self.source = dpkg['Source']
        self.version = dpkg['Version']
        self.architecture = dpkg['Architecture']
        # changelog
        debian_time = parse_changelog(self.changelog)
        if debian_time:
            self.timestamp = convert_debian_time_to_unix(debian_time)
        else:
            self.timestamp = -1
        # Dependencies
        try:
            depends = set(safe_split(dpkg['Depends']))
        except KeyError:
            depends = []
            self.logger.warning("Warning: %s has no Depends", self.deb)
        # Set forge as debian because they declared as Debian packages
        debian_dependencies = [parse_dependency(dep, 'debian')
                               for dep in depends]
        self.dependencies.extend(debian_dependencies)

    def gen_can_cgraph(self):
        """Generate canonical Call-Graph."""
        with open(self.cgraph, 'r') as fdr:
            edges = csv.reader(fdr, delimiter=' ')
            for edge in edges:
                can_edge = self._parse_edge(edge)
                # If the product of the first node is not the analyzed or
                # if the product of either nodes is in rules skip that edge
                if (can_edge[0].startswith('//') or
                    (any(r in can_edge[0] for r in self.rules) or
                     any(r in can_edge[1] for r in self.rules))):
                    continue
                self.can_graph.append(can_edge)
        self._add_orphan_dependenies()

    def save(self):
        data = {
            'product': self.product,
            'source': self.source,
            'version': self.version,
            'architecture': self.architecture,
            'forge': self.forge,
            'timestamp': self.timestamp,
            'depset': self.dependencies,
            'graph': self.can_graph
        }
        with open(self.output, 'w') as fdr:
            json.dump(data, fdr)

    def canonicalize(self):
        self.parse_files()
        self.gen_can_cgraph()
        self.save()

    def _set_logger(self, console_logging, file_logging, logging_level):
        self.logger = logging.getLogger('C canonicalizer')
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        # create formatter
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        if console_logging:
            # create console handler
            cons_h = logging.StreamHandler()
            cons_h.setLevel(logging_level)
            cons_h.setFormatter(formatter)
            self.logger.addHandler(cons_h)
        if file_logging:
            # create file handler
            file_h = logging.FileHandler(self.directory + '/fcan.log')
            file_h.setLevel(logging_level)
            file_h.setFormatter(formatter)
            self.logger.addHandler(file_h)

    def _parse_edge(self, edge):
        node1 = self._get_uri(edge[0])
        node2 = self._get_uri(edge[1])
        return (node1, node2)

    def _get_uri(self, node):
        product, namespace, function = self._parse_node(node)
        if (product not in get_product_names(self.dependencies) and
                product not in self.rules):
            if product != self.product:
                self.orphan_deps.add(product)
        return self._uri_generator(product, namespace, function)

    def _uri_generator(self, product, namespace, function):
        forge_product_version = ''
        if product != self.product:
            forge_product_version += '//' + product
        return '{}/{}/{}'.format(forge_product_version, namespace, function)

    def _parse_node(self, node):
        scope, path, entity = node.split(':')
        product = self._find_product(path)
        if scope == 'static':
            namespace = path[:path.rfind('/')]
            # TODO Create pct_encode function
            namespace = namespace.replace('/', '%2F')
            function = path[path.rfind('/')+1:] + ';' + entity + '()'
        else:
            namespace = 'C'
            function = entity + '()'
        return product, namespace, function

    def _find_product(self, path):
        stdout, status = find_product(path)
        if status == 0:
            return stdout.decode(encoding='utf-8').split(':')[0]
        if re.match(r'' + self.product_regex, path):
            self.logger.debug("product match: %s", path)
            return self.product
        if path.startswith('./'):
            return self.product
        if self.custom_deps is not None:
            product = check_custom_deps(path, self.custom_deps)
            if product is not None:
                return product
        self.logger.debug("UNDEF match: %s", path)
        return "UNDEF"

    def _add_orphan_dependenies(self):
        """Add products that dpkg detected but we don't have them as deps.

        Orphan dependencies are probably Essential packages. You can find more
        about essential packages here:
            https://www.debian.org/doc/debian-policy/ch-binary.html#essential-packages
        """
        for orph in self.orphan_deps:
            # TODO Handle special cases like libc
            self.dependencies.append({
                'forge': 'debian',
                'product': orph,
                'architectures': '',
                'constraints': ''})


def main():
    """Main function of fcan.py.

    Parse command line arguments and execute the Canonicalizer.
    """
    parser = argparse.ArgumentParser(description=(
        'Canonicalize Call Graphs to FASTEN Canonical Call Graphs'))
    parser.add_argument('directory', help=(
        'a directory with the Call Graph, and description files'))
    parser.add_argument('-f', '--forge', default='debian', help=(
        'forge of the analyzed project. For example, it could be debian, '
        'or GitHub'))
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='print logs to the console')
    parser.add_argument('-L', '--file-logging', dest='file_logging',
                        action='store_true',
                        help='save logs to a file')
    parser.add_argument('-l', '--logging-level', dest='logging_level',
                        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO',
                                 'DEBUG'],
                        default='DEBUG', help='logging level for logs')
    parser.add_argument('-c', '--custom-deps', dest='custom_deps',
                        default=None, help='custom user defined dependencies')
    parser.add_argument('-r', '--regex-product', dest='regex_product',
                        default=None, help='regex to match product\'s files')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='file to save the canonicalized call graph')
    args = parser.parse_args()
    can = C_Canonicalizer(args.directory,
                          forge=args.forge,
                          console_logging=args.verbose,
                          file_logging=args.file_logging,
                          logging_level=args.logging_level,
                          custom_deps=args.custom_deps,
                          product_regex=args.regex_product)
    can.canonicalize()


if __name__ == "__main__":
    main()
