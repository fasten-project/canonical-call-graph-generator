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
import glob
import subprocess as sp
import pkg_resources
from datetime import datetime


# Special value to give to nodes when the defined bit is off
UNDEFINED_PRODUCT = 'UNDEFINED'
# https://www.debian.org/doc/debian-policy/ch-relationships.html
BINARY_DEPENDENCIES = [
    'Depends', 'Recommends', 'Suggests', 'Enhances', 'Pre-Depends'
]
BUILD_DEPENDENCIES = [
    'Built-Using', 'Build-Depends', 'Build-Depends-Indep', 'Build-Depends-Arch'
]


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


def parse_dependency(dep, forge, dep_type, virtuals={}, strip_udeb=False):
    """Parse a dependency and return a dictionary in the FASTEN format.

    Args:
        dep: A string that contains a dependency. It may include alternatives
        dependencies (|), specific versions (inside parentheses), and specific
        architectures (inside brackets).
        forge: debian, or github, etc.
        dep_type: The dependency type.
        virtuals: Map of virtual packages to the packages they produced them.
            This is needed for Debian packages, to check if a dependency is
            virtual.
        strip_udeb: Boolean

    Returns:
        A dict mappings values to the corresponding fields.
        A fasten dependency must contain forge-product, and may contain
        constraints and architectures (if they don't exist, it returns empty
        strings).
        In case of alternative dependencies it includes a field
        called alternative that has a list of alternative dependencies.

    Examples:
        1) input: "debhelper (>= 9)"
           return:
                {
                 'product': 'debhelper',
                 'forge': 'debian',
                 'architectures': [],
                 'constraints': '[9,)',
                 'dependency_type': 'Depends',
                 'is_virtual': False,
                 'alternatives': []
                }

        2) input: "libdebian-installer4-dev [amd64] | libdebconfclient-dev"
           return:
                {
                 'product': 'libdebconfclient-dev',
                 'forge': 'debian',
                 'architectures': [],
                 'constraints': '',
                 'dependency_type': 'Depends',
                 'is_virtual': False,
                 'alternatives': [
                    {
                     'product': 'libdebian-installer4-dev'
                     'forge': 'debian',
                     'architectures': ['amd64']
                     'constraints': '',
                     'dependency_type': 'Depends',
                     'is_virtual': False,
                     'alternatives': []
                    }
                 ]
                }
    """
    if '|' in dep:
        dependencies = [
            parse_dependency(alt, forge, dep_type, virtuals, strip_udeb)
            for alt in dep.split('|')
        ]
        main_dep = dependencies[0]
        dependencies.remove(main_dep)
        main_dep['alternatives'] = dependencies
        return main_dep
    dep = dep.strip()
    name = ''
    version = ''
    arch = ''
    version, dep = extract_text(dep)
    arch, dep = extract_text(dep, ('[', ']'))
    arch = list(filter(None, arch.split()))
    _, dep = extract_text(dep, ('<', '>'))
    name = dep.strip()
    name = name[:-5] if name.endswith('-udeb') else name
    virtual = True if dep in virtuals else False
    return {'product': name, 'forge': forge, 'architectures': arch,
            'constraints': use_mvn_spec(version), 'dependency_type': dep_type,
            'is_virtual': virtual, 'alternatives': []}


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
        The full path of a file. In case of shared libraries it should be only
        their name and not their path.

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


def parse_dsc_file(filename):
    """Parse a .dsc file.

    Args:
        filename: filename of changelog

    Returns:
        dict with the following keys:

    """
    res = {}
    with open(filename, 'r') as f:
        lines = f.readlines()
        lines = [l.strip() for l in lines]
        for line in lines:
            if line.startswith('Built-Using'):
                res['Built-Using'] = line[line.find(':')+1:].strip()
            elif line.startswith('Build-Depends'):
                res['Build-Depends'] = line[line.find(':')+1:].strip()
            elif line.startswith('Build-Depends-Indep'):
                res['Build-Depends-Indep'] = line[line.find(':')+1:].strip()
            elif line.startswith('Build-Depends-Arch'):
                res['Build-Depends-Arch'] = line[line.find(':')+1:].strip()
    return res


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
        elif line.startswith('Version:'):
            res['Version'] = line[line.find(':')+1:].strip()
        elif line.startswith('Architecture:'):
            res['Architecture'] = line[line.find(':')+1:].strip()
        elif line.startswith('Depends:'):
            res['Depends'] = line[line.find(':')+1:].strip()
        elif line.startswith('Suggests:'):
            res['Suggests'] = line[line.find(':')+1:].strip()
        elif line.startswith('Recommends:'):
            res['Recommends'] = line[line.find(':')+1:].strip()
        elif line.startswith('Enhances:'):
            res['Enhances'] = line[line.find(':')+1:].strip()
        elif line.startswith('Pre-Depends:'):
            res['Pre-Depends'] = line[line.find(':')+1:].strip()
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


def canonicalize_path(path, prefix=None):
    """Canonicalize a given path.

    Remove the prefix from the path. Otherwise, if the path starts with
    /build/XXX/package-version then remove this prefix.

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


def canonicalize_binary_name(binary):
    """Return the basename of a binary and only the first part of the
        extension.

    For example, /lib/x86_64-linux-gnu/libc.so.6 would become libc.so
    """
    basename = os.path.basename(binary)
    second_dot = basename.find('.', basename.find('.') + 1)
    return basename[:second_dot] if second_dot > -1 else basename


def find_shared_libs_products(binary):
    """Find linked shared libraries and their corresponding products.

    Sometimes to get the correct product of a shared library we must know
    the binary that is linked to.

    Args:
        The file path of a binary

    Returns:
        A list that contains tuples with shared libraries paths, and
        their products
    """
    res = []
    # Run ldd to detect the shared libraries
    stdout, _ = run_command(['ldd', '-d', binary])
    solib_names_paths = []  # (name, path or '')
    for line in stdout:
        if len(line.split()) == 0:
            continue
        elif "=>" in line:
            name = line.split('=>')[0].split()[0]
            path = line.split('=>')[1].split()[0]
            if path == 'not':  # library not found
                # add the library in the results with library name
                continue
            solib_names_paths.append((name, path))
        elif line.split()[0].startswith('/'):
            solib_names_paths.append((line.split()[0], (line.split()[0])))
    # Run dpkg to detect products
    for name, path in solib_names_paths:
        stdout, status = run_command(['dpkg', '-S', name])
        stdout = list(filter(None, stdout))
        if len(stdout) > 1:
            product = re.split(':| ', stdout[0])[0]
            for line in stdout:
                if line.split(' ')[1] == path:
                    product = re.split(':| ', line)[0]
        else:
            product = stdout = re.split(':| ', stdout[0])[0]
        if status != 0:
            product = 'UNDEFINED'
        res.append((path, product))
    return res


def find_static_libraries_products(cs, aproduct, product_regex):
    """Find static libraries and their corresponding products.

    Args:
        cs: The file path of a cscout file
        aproduct: Analyzed product
        product_regex: Regex to match libraries of analyzed product

    Returns:
        A list that contains tuples with static libraries path, and
        their products
    """
    res = []
    libraries = set()
    # Find libraries
    with open(cs, 'r') as f:
        for line in f.readlines():
            if line.startswith('#pragma echo "LIBRARIES'):
                libraries.update(line.strip()[24:-3].split())
    # Run dpkg to detect products
    for path in libraries:
        stdout, status = run_command(['dpkg', '-S', path])
        if status != 0:
            if re.match(r'' + product_regex, path):
                product = aproduct
            else:
                product = UNDEFINED_PRODUCT
        else:
            product = re.split(':| ', stdout[0])[0]
        res.append((path, product))
    return res


class C_Canonicalizer:
    """A canonicalizer that transforms C Call-Graphs to FASTEN Call-Graphs

    You should always run this tool in the environment where the Call-Graph
    produced. The format of the cgraph must be an edge list separated by space.

    **Currently it only supports Debian Packages analyzed by CScout**

    To use:
        can = C_Canonicalizer('file.deb', 'file.dsc', 'changelog', 'binaries')
        can.canonicalize()
    """

    def __init__(self, deb, dsc, changelog, binaries, forge="debian",
                 source="", console_logging=True, file_logging=False,
                 logging_level='DEBUG', custom_deps=None,
                 product_regex=None, output=None, analyzer="",
                 defined_bit=False, virtuals={}, release=""
                 ):
        """C_Canonicalizer constructor.

        Args:
            deb: deb or udeb filename.
            dsc: dsc filename.
            changelog: changelog file.
            binaries: directory that contains directories with the analyzed
                binaries.
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
            virtuals: Map from virtual packages to list of packages that
                implements them.
            release: Debian Release
        Attributes:
            deb: deb or udeb filename.
            dsc: dsc filename.
            changelog: changelog file.
            binaries:  dictionary with analyzed binaries' names as keys and a
                dict with graph, binary, and cs as values.
            forge: Product's forge.
            release: Debian Release
            product: Product's name.
            source: Source's name.
            version: Product's version (string).
            version: Product's architecture.
            timestamp: seconds form epoch.
            dependencies: Product's dependencies.
            build_dependencies: Product's build dependencies.
            dependencies_lookup: A map from host packages to dependencies.
            can_graph: Canonicalized Call-Graph.
            cha: A dictionary containing URIs of nodes' declarations
                categorized based on binaries or static functions.
            current_binary: Current analyzed binary
            node_id_counter: A counter to set node ids
            nodes: Nodes of analyzed product
            environment_deps: Dependencies that are not declared in deb.
            virtuals: Map from virtual packages to list of packages that
                implements them.
        Raise:
            CanonicalizationError: if any of the input files does not exist or
                is empty
        """
        self._set_logger(console_logging, file_logging, logging_level)

        self.deb = deb
        self.dsc = dsc
        self.changelog = changelog
        self.virtuals = virtuals
        self.release = release
        self.binaries = {}
        self.forge = forge
        self.product = None
        self.source = source
        self.version = None
        self.architecture = None
        self.timestamp = None
        self.can_graph = {'externalCalls': [], 'internalCalls': []}
        self.cha = {'binaries': {}, 'static_functions': {}}
        self.analyzer = analyzer
        self.defined_bit = defined_bit
        self.node_id_counter = 0

        if not (os.path.exists(self.deb) and os.path.getsize(self.deb) > 0):
            raise CanonicalizationError("deb file not exist or empty")
        if not (os.path.exists(self.dsc) and os.path.getsize(self.dsc) > 0):
            raise CanonicalizationError("dsc file not exist or empty")
        if not (os.path.exists(self.changelog) and
                os.path.getsize(self.changelog) > 0):
            raise CanonicalizationError("changelog file not exist or empty")
        if not (os.path.exists(binaries) and os.path.isdir(binaries)):
            raise CanonicalizationError("binaries directory not exist")
        binaries = glob.glob(os.path.abspath(binaries + '/*'))
        if not binaries:
            raise CanonicalizationError("binaries directory is empty")
        for binary in binaries:
            files = glob.glob(os.path.abspath(binary + '/*'))
            try:
                graph = list(filter(lambda x: x.endswith('.txt'), files))[0]
            except IndexError:
                self.logger.warning('binary: %s has not a graph', binary)
                continue
            try:
                cs_file = list(filter(lambda x: x.endswith('.cs'), files))[0]
            except IndexError:
                self.logger.warning('binary: %s has not a cscout file', binary)
                continue
            try:
                binary_file = list(filter(
                    lambda x: not x.endswith('.txt') and not x.endswith('.cs'),
                    files)
                )[0]
            except IndexError:
                self.logger.warning('binary: %s has not a binary', binary)
                continue
            can_binary = canonicalize_binary_name(binary_file)
            self.cha['binaries'][can_binary] = {}
            self.binaries[can_binary] = {
                'binary': binary_file,
                'cs': cs_file,
                'graph': graph
            }
        if not self.binaries:
            raise CanonicalizationError("No binaries detected")

        # A cache to minimize the calls of find_product
        self.find_product_cache = {}

        # Nodes that contain one of those values are skipped from the canonical
        # Call-Graph
        self.rules = ['NULL']

        self.dependencies = []
        self.build_dependencies = []
        self.dependencies_lookup = {}
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
                        "architecture": value['architecture'],
                        "dependency_type": "custom",
                        "is_virtual": False,
                        "alternatives": {}
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
        # dsc file
        dsc = parse_dsc_file(self.dsc)
        # changelog
        debian_time = parse_changelog(self.changelog, self.version)
        if debian_time:
            self.timestamp = convert_debian_time_to_unix(debian_time)
        else:
            self.timestamp = -1
        # Dependencies
        for dep_type in BINARY_DEPENDENCIES:
            if dep_type in dpkg:
                self._parse_dependencies(dpkg[dep_type], dep_type)
            else:
                self.logger.warning(
                    "Warning: %s has no %s", self.deb, dep_type)
        for dep_type in BUILD_DEPENDENCIES:
            if dep_type in dsc:
                self._parse_dependencies(dsc[dep_type], dep_type, True)
            else:
                self.logger.warning(
                    "Warning: %s has no %s", self.dsc, dep_type)
        # Parse binaries
        for binary, values in self.binaries.items():
            functions = {}
            solibs = find_shared_libs_products(values['binary'])
            static_libraries = find_static_libraries_products(
                values['cs'], self.product, self.product_regex
            )
            for solib, product in solibs:
                self._detect_functions(solib, product, functions, False)
            for static_lib, product in static_libraries:
                self._detect_functions(static_lib, product, functions, True)
            self.binaries[binary]['functions'] = functions

    def gen_can_cgraph(self):
        """Generate canonical Call-Graph."""
        for binary in self.binaries.keys():
            self._parse_graph(binary)

    def _parse_graph(self, binary):
        """Generate canonical Call-Graph."""
        self.current_binary = binary
        with open(self.binaries[binary]['graph'], 'r') as fdr:
            # An element could be a node declaration, or an edge of the call
            # graph
            elements = csv.reader(fdr, delimiter=' ')
            for el in elements:
                if len(el) == 1:
                    can_node, path = self._parse_node_declaration(el[0])
                    # Insert nodes only from the analyzed product.
                    # External nodes contain 5 slashes.
                    if can_node.startswith('//'):
                        continue
                    if path.endswith('.cs'):  # Skip cscout files
                        continue
                    # Static function
                    if ';' in can_node.split('/')[-1]:
                        target = self.cha['static_functions']
                    else:
                        target = self.cha['binaries'][binary]
                    if can_node not in target:
                        target[can_node] = {
                            "id": self.node_id_counter,
                            "files": [path]
                        }
                        self.node_id_counter += 1
                    elif path not in target[can_node]['files']:
                        target[can_node]['files'].append(path)
                        self.node_id_counter += 1
                else:
                    can_edge = self._parse_edge(el)
                    # If the product of the first node is not the analyzed or
                    # if the product of either nodes is in rules skip that edge
                    if (can_edge[0].startswith('//') or
                        (any(r in can_edge[0] for r in self.rules) or
                         any(r in can_edge[1] for r in self.rules))):
                        continue
                    if can_edge[0] in self.cha['static_functions']:
                        target = self.cha['static_functions']
                    elif can_edge[0] in self.cha['binaries'][binary]:
                        target = self.cha['binaries'][binary]
                    else:
                        self.logger.warning("Warning: node %s is not defined",
                                            can_edge[0]
                                            )
                        continue
                    can_edge[0] = target[can_edge[0]]['id']
                    if can_edge[1] in self.cha['static_functions']:
                        target = self.cha['static_functions']
                    elif can_edge[1] in self.cha['binaries'][binary]:
                        target = self.cha['binaries'][binary]
                    else:
                        target = False
                    if target:
                        can_edge[1] = target[can_edge[1]]['id']
                        self.can_graph['internalCalls'].append(can_edge)
                    else:
                        can_edge[0] = str(can_edge[0])
                        if not can_edge[1].startswith('//'):
                            can_edge[1] = '///{}'.format(
                                can_edge[1][can_edge[1].find(';'):]
                            )
                        self.can_graph['externalCalls'].append(can_edge)

    def save(self):
        data = {
            'forge': self.forge,
            'release': self.release,
            'product': self.product,
            'version': self.version,
            'source': self.source,
            'architecture': self.architecture,
            'generator': self.analyzer,
            'timestamp': self.timestamp,
            'depset': self.dependencies,
            'build_depset': self.build_dependencies,
            'undeclared_depset': self._get_environment_dependenies(),
            'graph': self.can_graph,
            'cha': self.cha
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
            file_h = logging.FileHandler('fcan.log')
            file_h.setLevel(logging_level)
            file_h.setFormatter(formatter)
            self.logger.addHandler(file_h)

    def _parse_dependencies(self, string, dep_type, is_build_dep=False):
        """This method parses a string that contain dependencies and append
        them to either self.dependencies or self.build_dependencies.
        It also updates self.dependencies_lookup.

        If the is_build_dep flag is true then it appends the parsed
        dependencies to self.build_dependencies, otherwise to self.dependencies.

        * For regular dependencies adds `product: product` into
        dependencies_lookup.
        * For alternatives adds `alt_product: original_product` into
        dependencies_lookup, where original_product is the alternative with
        higher priority.
        * For virtual packages finds all products that provide the virtual
        package and adds product: `virtual_product`. If the virtual package is
        in alternatives then add the original product instead of virtual_product
        """
        deps = set(safe_split(string))
        # Set forge as debian because they declared as Debian packages
        deps = [parse_dependency(dep, 'debian', dep_type, self.virtuals, True)
                for dep in deps]
        if is_build_dep:
            self.build_dependencies.extend(deps)
        else:
            self.dependencies.extend(deps)
        # Update self.dependencies_lookup
        for dep in deps:
            self.dependencies_lookup[dep['product']] = dep['product']
            for alt in dep['alternatives']:
                self.dependencies_lookup[alt['product']] = dep['product']
                self._add_virtuals(alt, dep['product'])
            self._add_virtuals(dep, dep['product'])

    def _add_virtuals(self, dep, base_product):
        """Check if a product is virtual, and if it is add the products that
        provide it to self.dependencies_lookup.
        """
        if dep['is_virtual']:
            if dep['product'] in self.virtuals:
                for p in self.virtuals[dep['product']]:
                    self.dependencies_lookup[p] = base_product
            else:
                self.logger.warning("Warning: %s not in self.virtuals",
                                    dep['product']
                                    )

    def _detect_functions(self, library, product, functions, is_static=True):
        """Fill functions with all the functions detected in the provided
        library.
        """
        # Find product in dependencies
        if product not in self.dependencies_lookup:
            if product == self.product:
                resolved_product = self.product
            elif product == UNDEFINED_PRODUCT:
                resolved_product = UNDEFINED_PRODUCT
            else:
                resolved_product = product
                self.environment_deps.add(product)
                self.logger.warning(
                    "Warning: %s not found in dependencies", product
                )
        else:
            resolved_product = self.dependencies_lookup[product]
        # Find functions
        can_library = canonicalize_binary_name(library)
        if is_static:
            stdout, _ = run_command(['nm', '-g', library])
            for line in stdout:
                line = line.strip().split()
                if len(line) == 3 and line[1] == 'T':
                    functions[line[2]] = (can_library, resolved_product)
        else:
            stdout, _ = run_command(['objdump', '-T', library])
            for line in stdout:
                if 'DF .text' in line or 'iD  .text' in line:
                    name = line.split()[-1]
                    if (name in functions and
                            resolved_product != functions[name]):
                        self.logger.debug(
                            "Warning: %s (%s) already found in %s",
                            name, resolved_product, functions[name]
                        )
                    functions[name] = (can_library, resolved_product)

    def _parse_node_declaration(self, node):
        """Returns uri, and path. We need path separately to save the filename
           of the file when needed.
        """
        _, _, path, _ = self._parse_node_string(node)
        path = canonicalize_path(path, self.product_regex)
        can_uri = self._get_uri(node)
        return can_uri, path

    def _parse_edge(self, edge):
        node1 = self._get_uri(edge[0])
        node2 = self._get_uri(edge[1])
        return [node1, node2]

    def _get_uri(self, node):
        product, binary, namespace, function, is_static = self._parse_node(
            node)
        forge_product_version = ''
        if product != self.product:
            if binary.endswith('.so') or (binary == '' and not is_static):
                product = ''
            forge_product_version += '//' + product
        return '{}/{};{}/{}'.format(
            forge_product_version, binary, namespace, function
        )

    def _parse_node_string(self, node):
        """We need this function because we may support more formats in the
           future.
        """
        # FIXME maybe we don't need is_defined
        is_defined = True
        if self.defined_bit:
            scope, is_defined, path, entity = node.split(':')
            is_defined = False if is_defined == '0' else True
        else:
            scope, path, entity = node.split(':')
        return scope, is_defined, path, entity

    def _parse_node(self, node):
        scope, _, path, entity = self._parse_node_string(node)
        is_static = True if scope == 'static' else False
        product = self._find_product(path, entity)
        binary = self._find_binary(entity, product, is_static)
        if is_static:
            namespace = canonicalize_path(path, self.product_regex)
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
        return product, binary, namespace, function, is_static

    def _find_binary(self, function, product, is_static):
        if is_static:
            return ''
        # TODO Maybe we should check if it comes from a another shared library
        # of the same product.
        if product == self.product:
            return self.current_binary
        if function in self.binaries[self.current_binary]['functions']:
            return self.binaries[self.current_binary]['functions'][function][0]
        self.logger.debug(
            "Warning: could not detect binary of function %s, from product %s",
            function, product
        )
        return ''

    def _find_product(self, path, function):
        product = None
        # Check if function is in the functions found in shared libraries
        if function in self.binaries[self.current_binary]['functions']:
            product = self.binaries[self.current_binary]['functions'][function][1]
        # Check if path is in find_product_cache
        if path in self.find_product_cache and product is None:
            stdout, status = self.find_product_cache[path]
            product = stdout if status == 0 else UNDEFINED_PRODUCT
        # Check if the callable belongs to the analyzed product
        if re.match(r'' + self.product_regex, path) and product is None:
            self.logger.debug("product match: %s", path)
            product = self.product
        # Check if it is a product from custom deps based on the path
        if self.custom_deps is not None and product is None:
            product = check_custom_deps(path, self.custom_deps)
        # Detect product by examining the path
        if path not in self.find_product_cache and product is None:
            stdout, status = find_product(path)
            self.find_product_cache[path] = (stdout, status)
            product = stdout if status == 0 else UNDEFINED_PRODUCT
        if not path.startswith('/') and product is None:
            product = self.product
        if product is None:
            self.logger.warning(
                "Warning: UNDEFINED match: path %s, function %s", path, function
            )
            return UNDEFINED_PRODUCT
        else:
            if (product not in self.dependencies_lookup and
                    product not in self.rules and
                    product != self.product and
                    product not in self.environment_deps and
                    product != UNDEFINED_PRODUCT):
                self.logger.warning(
                    "Warning: %s not found in dependencies", product
                )
                self.environment_deps.add(product)
            return product

    def _get_environment_dependenies(self):
        """Add products that dpkg detected but we don't have them as deps.

        Environment dependencies are probably Essential packages.
        You can find more about essential packages here:
        https://www.debian.org/doc/debian-policy/ch-binary.html#essential-packages
        """
        depset = []
        for prod in self.environment_deps:
            depset.append({
                'forge': 'debian',
                'product': prod,
                'architectures': '',
                'constraints': '',
                'dependency_type': '',
                'is_virtual': False,
                'alternatives': []
            })
        return depset


def main():
    """Main function of fcan.py.

    Parse command line arguments and execute the Canonicalizer.
    """
    parser = argparse.ArgumentParser(description=(
        'Canonicalize Call Graphs to FASTEN Canonical Call Graphs'))
    parser.add_argument('deb', help='deb or udeb file of package')
    parser.add_argument('dsc', help='dsc file of package')
    parser.add_argument('changelog', help='changelog file of package')
    parser.add_argument(
        'binaries',
        help=(
            'Directory that contain a directory for each analyzed binary. '
            'Each should have the name of the binary without the '
            'extension, and should contain the binary, a txt file with'
            'the call graph in a comma separated edge list, and a .cs'
            'file produced by csmake to get the linked static libraries.'
        )
    )
    parser.add_argument(
        '-f', '--forge',
        default='debian',
        help=(
                'Forge of the analyzed project. For example, '
                'it could be debian, or GitHub'
        )
    )
    parser.add_argument(
        '-v', '--verbose', dest='verbose',
        action='store_true',
        help='print logs to the console'
    )
    parser.add_argument(
        '-L', '--file-logging', dest='file_logging',
        action='store_true',
        help='save logs to a file'
    )
    parser.add_argument(
        '-l', '--logging-level', dest='logging_level',
        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'],
        default='DEBUG',
        help='logging level for logs'
    )
    parser.add_argument(
        '-c', '--custom-deps', dest='custom_deps',
        default=None,
        help='custom user defined dependencies'
    )
    parser.add_argument(
        '-r', '--regex-product', dest='regex_product',
        default=None,
        help='regex (of prefix) to match product\'s files'
    )
    parser.add_argument(
        '-s', '--source',
        default='',
        help='product\'s source'
    )
    parser.add_argument(
        '-o', '--output', dest='output',
        default=None,
        help='file to save the canonicalized call graph'
    )
    parser.add_argument(
        '-a', '--analyzer',
        default='',
        help='Analyzer used to generate the call graphs'
    )
    parser.add_argument(
        '-R', '--release',
        choices=['buster', 'bullseye'],
        help=(
            'Debian Release. This option is used to get '
            'the virtual packages of a release'
        )
    )
    parser.add_argument(
        '-d', '--defined-bit', dest='defined_bit',
        action='store_true',
        help=(
            'Check for bit that declares if a function is '
            'defined. In this case a node should have the '
            'following format: '
            'static|public:0|1:path:function_name'
        )
    )
    args = parser.parse_args()
    virtuals = {}
    if args.release:
        # Load the virtual packages of the specified Debian release
        release = pkg_resources.resource_filename(
            __name__, 'data/virtual/{}.json'.format(args.release)
        )
        with open(release, 'r') as f:
            virtuals = json.load(f)
        release = args.release
    else:
        release = ''

    can = C_Canonicalizer(
        args.deb,
        args.dsc,
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
        defined_bit=args.defined_bit,
        virtuals=virtuals,
        release=release
    )
    can.canonicalize()


if __name__ == "__main__":
    main()
