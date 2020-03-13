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


# Special value to give to nodes when the defined bit is off
UNDEFINED_PRODUCT = 'UNDEFINED'


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


def run_command(arguments, parse_stdout=True):
    """Run a command

    Args:
        A list with the arguments to execute. For example ['ls', 'foo']

    Returns:
        stdout, return status.
    """
    try:
        cmd = sp.Popen(arguments, stdout=sp.PIPE, stderr=sp.STDOUT)
        stdout, _ = cmd.communicate()
    except Exception as e:
        m = "Warning: run_command failed with arguments {} and error {}".format(
            ' '.join(map(str, arguments)), e
        )
        print(m)
        return '', -1
    if parse_stdout:
        stdout = stdout.decode("utf-8").split("\n")
    status = cmd.returncode
    return stdout, status


def find_product(path):
    """Find the corresponding product of a file.

    Args:
        The full path of a file.

    Returns:
        stdout, return status.
    """
    stdout, status = run_command(['dpkg', '-S', path])
    stdout = re.split(':| ', stdout[0])[0]
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


def parse_changelog(filename, version):
    """Parse Debian syntax changelog files and return last date.

    Args:
        filename: filename of changelog
    Returns:
        date in the format day-of-week, dd month yyyy hh:mm:ss +zzzz or -1
    """
    check_line = False
    with open(filename, 'r') as changelog:
        for line in changelog.readlines():
            if check_line:
                if re.match(r'^ .*<.*@.*>  [A-Z][a-z][a-z], [0-9][0-9]', line):
                    return re.split(r'^ .*<.*@.*>', line)[1].strip()
            else:
                m = re.match(r'^.* \((.*)\)', line)
                if m:
                    if m.groups()[0] == version:
                        check_line = True


def parse_deb_file(filename):
    """Parse a .deb or .udeb file using dpkg -I

    Args:
        filename: filename of changelog

    Returns:
        dict: with the following keys; Package, Source, Version, Architecture,
            and Depends (not always)
    """
    stdout, _ = run_command(['dpkg', '-I', filename], False)
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


def find_undefined_functions_util(objdump_out):
    """Find undefined functions from objdump output.

    Args:
        The output of objdump command.

    Returns:
        A list that contains function names
    """
    return [line.split()[-1] for line in objdump_out if "*UND*" in line]


def find_undefined_functions(binary):
    """Find the undefined functions of a binary.

    The binary could be an executable, a shared library, or a static library.
    We use the objdump util to find the undefined functions.

    Args:
        The file path of a binary

    Returns:
        A list that contains function names
    """
    stdout, _ = run_command(['objdump', '-T', binary])
    return find_undefined_functions_util(stdout)


def filter_shared_libs(line):
    """Helper function that checks there is a valid shared library in a line
    """
    if len(line.split()) == 0:
        return
    elif "=>" in line:
        return line.split('=>')[1].split()[0]
    elif line.split()[0].startswith('/'):
        return line.split()[0]


def find_shared_libs_util(ldd_out):
    """Find shared libraries for ldd output.

    Args:
        The output of ldd command.

    Returns:
        A list that contains shared libraries names
    """
    return list(filter(None, map(filter_shared_libs, ldd_out)))


def find_shared_libs(binary):
    """Find linked shared libraries.

    Args:
        The file path of a binary

    Returns:
        A list that contains shared libraries names.
    """
    stdout, _ = run_command(['ldd', '-d', binary])
    return find_shared_libs_util(stdout)


def filter_product(line):
    """Helper functions to find which package contains a shared library
    from ldd output line.
    """
    if len(line.split()) == 0:
        return
    elif "=>" in line or line.split()[0].startswith('/'):
        lib = line.strip().split()[0]
        stdout, _ = find_product(lib)
        return stdout


def match_products(init_products, test_products):
    """Match products from one list to products of another list

    Some times two product names may refer to the same product. For example,
    libc6-udeb refer to libc6 but without the documentation. In such cases,
    although that in the dependencies of a package lib6-udeb is declared,
    dpkg detect libc6.

    Args:
        init_products: Usually the dependencies of a Debian package
        test_products: Usually products found using dpkg

    Returns:
        A list that contains the match from every product from init_products
        to test_products.
    """
    remove_udeb = lambda x : x[:-5] if x.endswith('-udeb') else x
    test_products = list(map(remove_udeb, test_products))
    # FIXME
    return [p for p in init_products if p in test_products]



def find_pkg_of_solib(binary, products):
    """For each shared library linked to a binary find its package.

    Args:
        binary: The file path of a binary
        products: Packages to match to. Usually the dependencies of a package.

    Returns:
        A list that contains Debian packages names.
    """
    stdout, _ = run_command(['ldd', '-d', binary])
    init_products = list(filter(None, map(filter_product, stdout)))
    return match_products(init_products, products)


class C_Canonicalizer:
    """A canonicalizer that transforms C Call-Graphs to FASTEN Call-Graphs

    You should always run this tool in the environment where the Call-Graph
    produced. The format of the cgraph must be an edge list separated by space.

    **Currently it only supports Debian Packages**

    To use:
        can = C_Canonicalizer('file.deb', 'cgraph.txt', 'changelog')
        can.canonicalize()
    """
    def __init__(self, deb, cgraph, changelog, binaries, forge="debian",
                 source="", console_logging=True, file_logging=False,
                 logging_level='DEBUG', custom_deps=None,
                 product_regex=None, output=None, analyzer="",
                 defined_bit=False
                ):
        """C_Canonicalizer constructor.

        Args:
            deb: deb or udeb filename.
            cgraph: Call-Graph filename.
            changelog: changelog file.
            changelog: directory that contains analyzed binaries.
            forge: The forge of the analyzed package.
            console_logging: Enable logs to appear in stdout.
            file_logging: Create a file called debug.log in the 'directory'
                with the logs.
            custom_deps: User defined dependencies and constraints
            product_regex: Regex to match products files
            output: File to save the canonicalized call graph
            analyzer: Analyzer used to generate the call graphs.
            defined_bit: Input nodes have a bit to declare if a function is
                defined or not.
        Attributes:
            cgraph: Call-Graph filename.
            deb: deb or udeb filename.
            changelog: changelog file.
            binaries: list with analyzed binaries.
            forge: Product's forge.
            product: Product's name.
            source: Source's name.
            version: Product's version (string).
            version: Product's architecture.
            timestamp: seconds form epoch.
            dependencies: Product's dependencies (dict or list).
            can_graph: Canonicalized Call-Graph.
            environment_deps: Dependencies that are not declared in deb.
        Raise:
            CanonicalizationError: if .txt or .deb files not found.
        """
        self._set_logger(console_logging, file_logging, logging_level)

        self.deb = deb
        self.cgraph = cgraph
        self.changelog = changelog

        if not (os.path.exists(self.deb) and os.path.getsize(self.deb) > 0):
            raise CanonicalizationError("deb file not exist or empty")
        if not (os.path.exists(self.cgraph) and
                os.path.getsize(self.cgraph) > 0):
            raise CanonicalizationError("cgraph file not exist or empty")
        if not (os.path.exists(self.changelog) and
                os.path.getsize(self.changelog) > 0):
            raise CanonicalizationError("changelog file not exist or empty")
        if not (os.path.exists(binaries) and os.path.isdir(binaries)):
            raise CanonicalizationError("binaries directory not exist")
        if not os.listdir(binaries):
            raise CanonicalizationError("binaries directory is empty")

        self.forge = forge
        self.product = None
        self.source = source
        self.version = None
        self.architecture = None
        self.timestamp = None
        self.can_graph = []
        self.analyzer = analyzer
        self.defined_bit = defined_bit

        # A cache to minimize the calls of find_product
        self.paths_lookup = {}

        # Nodes that contain one of those values are skipped from the canonical
        # Call-Graph
        self.rules = ['NULL']

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
            self.output = 'can_cgraph.json'

        self.environment_deps = set()

    def parse_files(self):
        # deb file
        dpkg = parse_deb_file(self.deb)
        self.product = dpkg['Package']
        self.version = dpkg['Version']
        self.architecture = dpkg['Architecture']
        # changelog
        debian_time = parse_changelog(self.changelog, self.version)
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
            # An element could be a node declaration, or an edge of the call
            # graph
            elements = csv.reader(fdr, delimiter=' ')
            for el in elements:
                if len(el) == 1:
                    self._parse_node_declaration(el)
                else:
                    can_edge = self._parse_edge(el)
                    # If the product of the first node is not the analyzed or
                    # if the product of either nodes is in rules skip that edge
                    # FIXME the startswith test must be done outside
                    if (can_edge[0].startswith('//') or
                        (any(r in can_edge[0] for r in self.rules) or
                         any(r in can_edge[1] for r in self.rules))):
                        continue
                    self.can_graph.append(can_edge)

    def save(self):
        data = {
            'product': self.product,
            'source': self.source,
            'version': self.version,
            'architecture': self.architecture,
            'forge': self.forge,
            'timestamp': self.timestamp,
            'depset': self.dependencies,
            'environment_depset': self._get_environment_dependenies(),
            'graph': self.can_graph,
            'analyzer': self.analyzer
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

    def _parse_node_declaration(self, node):
        pass


    def _parse_edge(self, edge):
        node1 = self._get_uri(edge[0])
        node2 = self._get_uri(edge[1])
        return (node1, node2)

    def _get_uri(self, node):
        product, namespace, function = self._parse_node(node)
        if (product not in get_product_names(self.dependencies) and
                product not in self.rules and product != UNDEFINED_PRODUCT):
            if product != self.product:
                self.environment_deps.add(product)
        return self._uri_generator(product, namespace, function)

    def _uri_generator(self, product, namespace, function):
        forge_product_version = ''
        if product != self.product:
            forge_product_version += '//' + product
        return '{}/{}/{}'.format(forge_product_version, namespace, function)

    def _parse_node(self, node):
        is_defined = True
        if self.defined_bit:
            scope, is_defined, path, entity = node.split(':')
            is_defined = False if is_defined == '0' else True
        else:
            scope, path, entity = node.split(':')
        if is_defined:
            print(path)
            product = self._find_product(path)
        else:
            product = UNDEFINED_PRODUCT
        if scope == 'static':
            namespace = canonicalize_path(path)
            # TODO Create pct_encode function
            slash = namespace.rfind('/')
            # The main directory of its product
            if slash <= 0:
                namespace = '.'
            else:
                namespace = namespace[:slash]
            namespace = namespace.replace('/', '%2F')
            function = path[path.rfind('/')+1:] + ';' + entity + '()'
        else:
            namespace = 'C'
            function = entity + '()'
        return product, namespace, function

    def _find_product(self, path):
        if path not in self.paths_lookup:
            stdout, status = find_product(path)
            self.paths_lookup[path] = (stdout, status)
        else:
            stdout, status = self.paths_lookup[path]
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
        if not path.startswith('/'):
            return self.product
        self.logger.debug("NULL match: %s", path)
        return "NULL"

    def _get_environment_dependenies(self):
        """Add products that dpkg detected but we don't have them as deps.

        Orphan dependencies are probably Essential packages. You can find more
        about essential packages here:
            https://www.debian.org/doc/debian-policy/ch-binary.html#essential-packages
        """
        depset = []
        for orph in self.environment_deps:
            depset.append({
                'forge': 'debian',
                'product': orph,
                'architectures': '',
                'constraints': ''})
        return depset


def main():
    """Main function of fcan.py.

    Parse command line arguments and execute the Canonicalizer.
    """
    parser = argparse.ArgumentParser(description=(
        'Canonicalize Call Graphs to FASTEN Canonical Call Graphs'))
    parser.add_argument('deb', help='deb or udeb file of package')
    parser.add_argument('cgraph', help='edgelist of call graph in txt file')
    parser.add_argument('changelog', help='changelog file of package')
    parser.add_argument('binaries',
            help='Directory with analyzed binaries')
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
    parser.add_argument('-s', '--source',
                        default='', help='product\'s source')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='file to save the canonicalized call graph')
    parser.add_argument('-a', '--analyzer', default='',
                        help='Analyzer used to generate the call graphs')
    parser.add_argument('-d', '--defined-bit', dest='defined_bit',
                        action='store_true',
                        help=('Check for bit that declares if a function is '
                              'defined. In this case a node should have the '
                              'following format: '
                              'static|public:0|1:path:function_name'
                             )
                       )
    args = parser.parse_args()
    can = C_Canonicalizer(
            args.deb,
            args.cgraph,
            args.changelog,
            args.binaries,
            forge=args.forge,
            source=args.source,
            console_logging=args.verbose,
            file_logging=args.file_logging,
            logging_level=args.logging_level,
            custom_deps=args.custom_deps,
            product_regex=args.regex_product,
            analyzer=args.analyzer,
            defined_bit=args.defined_bit
    )
    can.canonicalize()


if __name__ == "__main__":
    main()
