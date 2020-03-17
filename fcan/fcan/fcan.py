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
                 'architectures': '',
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
                 'architectures': '',
                 'constraints': '',
                 'dependency_type': 'Depends',
                 'is_virtual': False,
                 'alternatives': [
                    {
                     'product': 'libdebian-installer4-dev'
                     'forge': 'debian',
                     'architectures': 'amd64',
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
    name = dep.strip()
    name = name[:-5] if name.endswith('-udeb') else name
    virtual = True if dep in virtuals else False
    return {'product': name, 'forge': forge, 'architectures': arch,
            'constraints': use_mvn_spec(version), 'dependency_type': dep_type,
            'is_virtual': virtual, 'alternatives': []}


def get_product_names(dependencies):
    """Get product names from a list with dependencies"""
    names = set()
    for dep in dependencies:
        names.add(dep['product'])
        if 'alternatives' in dep:
            names.update([alt['product'] for alt in dep['alternatives']])
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
        elif line.startswith('Source:'):
            res['Source'] = line[line.find(':')+1:].strip()
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
    if prefix and path.startswith('/'):
        regex = '({})(.*)'.format(prefix)
        prefix_regex = re.match(regex, path)
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


def get_product_solib(solib):
    """Get the product (Debian Package) of a shared library.

    Args:
        Shared Library

    Returns:
        Product name
    """
    if '/' in solib:
        solib = solib.split('/')[-1]
    product_name, status = find_product(solib)
    if status != 0:
        return 'UNDEFINED'
    return product_name


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


def match_products(products, filter_products):
    """Match products from one list to products of another list

    Some times two product names may refer to the same product. For example,
    libc6-udeb refer to libc6 but without the documentation. In such cases,
    although that in the dependencies of a package lib6-udeb is declared,
    dpkg detect libc6.

    Args:
        products: Usually products found using dpkg
        filter_products: Usually the dependencies of a Debian package

    Returns:
        A list that contains the match from every product from init_products
        to test_products.
    """
    remove_udeb = lambda x : x[:-5] if x.endswith('-udeb') else x
    filter_products = list(map(remove_udeb, filter_products))
    # FIXME add tests
    return [p if p in filter_products else 'UNDEFINED' for p in products]


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
    def __init__(self, deb, dsc, cgraph, changelog, binaries, forge="debian",
                 source="", console_logging=True, file_logging=False,
                 logging_level='DEBUG', custom_deps=None,
                 product_regex=None, output=None, analyzer="",
                 defined_bit=False, virtuals={}, release=""
                ):
        """C_Canonicalizer constructor.

        Args:
            deb: deb or udeb filename.
            dsc: dsc filename.
            cgraph: Call-Graph filename.
            changelog: changelog file.
            binaries: directory that contains analyzed binaries.
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
            cgraph: Call-Graph filename.
            deb: deb or udeb filename.
            dsc: dsc filename.
            changelog: changelog file.
            binaries: list with analyzed binaries.
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
        self.cgraph = cgraph
        self.changelog = changelog
        self.virtuals = virtuals
        self.release = release

        if not (os.path.exists(self.deb) and os.path.getsize(self.deb) > 0):
            raise CanonicalizationError("deb file not exist or empty")
        if not (os.path.exists(self.dsc) and os.path.getsize(self.dsc) > 0):
            raise CanonicalizationError("dsc file not exist or empty")
        if not (os.path.exists(self.cgraph) and
                os.path.getsize(self.cgraph) > 0):
            raise CanonicalizationError("cgraph file not exist or empty")
        if not (os.path.exists(self.changelog) and
                os.path.getsize(self.changelog) > 0):
            raise CanonicalizationError("changelog file not exist or empty")
        if not (os.path.exists(binaries) and os.path.isdir(binaries)):
            raise CanonicalizationError("binaries directory not exist")
        self.binaries = glob.glob(os.path.abspath(binaries + '/*'))
        if not self.binaries:
            raise CanonicalizationError("binaries directory is empty")

        self.forge = forge
        self.product = None
        self.source = source
        self.version = None
        self.architecture = None
        self.timestamp = None
        self.can_graph = {'externalCalls': [], 'internalCalls': []}
        self.analyzer = analyzer
        self.defined_bit = defined_bit
        self.node_id_counter = 0
        self.nodes = {}

        # A dict with all functions of the shared libraries linked to the
        # binaries, we use this dict to detect the products of undefined
        # functions
        self.functions = {}

        # A cache to minimize the calls of find_product
        self.paths_lookup = {}

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
                self.logger.warning("Warning: %s has no %s", self.deb, dep_type)
        for dep_type in BUILD_DEPENDENCIES:
            if dep_type in dsc:
                self._parse_dependencies(dsc[dep_type], dep_type, True)
            else:
                self.logger.warning("Warning: %s has no %s", self.dsc, dep_type)

    def detect_functions(self):
        """Fill self.functions with all the functions detected in the shared
        libraries linked to self.binaries
        """
        solibs = set()
        for b in self.binaries:
            solibs.update(find_shared_libs(b))
        solibs = list(solibs)
        products = [get_product_solib(l) for l in solibs]
        for solib, product in zip(reversed(solibs), reversed(products)):
            stdout, _ = run_command(['objdump', '-T', solib])
            resolved_product = self.dependencies_lookup.get(
                    product, UNDEFINED_PRODUCT
            )
            if product not in self.dependencies_lookup:
                resolved_product = UNDEFINED_PRODUCT
                self.logger.warning(
                        "Warning: %s not found in dependencies", product
                )
            else:
                resolved_product = self.dependencies_lookup[product]
            for line in stdout:
                if 'DF .text' in line or 'iD  .text' in line:
                    name = line.split()[-1]
                    if (name in self.functions and
                            resolved_product != self.functions[name]):
                        self.logger.warning(
                            "Warning: %s (%s) already found in %s",
                            name, resolved_product, self.functions[name]
                        )
                    self.functions[name] = resolved_product

    def gen_can_cgraph(self):
        """Generate canonical Call-Graph."""
        with open(self.cgraph, 'r') as fdr:
            # An element could be a node declaration, or an edge of the call
            # graph
            elements = csv.reader(fdr, delimiter=' ')
            for el in elements:
                if len(el) == 1:
                    can_node, path = self._parse_node_declaration(el[0])
                    # Insert to self.nodes only nodes from analyzed product
                    if can_node.startswith('//'):
                        continue
                    if path.endswith('.cs'):  # Skip cscout files
                        continue
                    if can_node not in self.nodes:
                        self.nodes[can_node] = {
                                "id": self.node_id_counter,
                                "files": [path]
                        }
                        self.node_id_counter += 1
                    else:
                        self.nodes[can_node]['files'].append(path)
                else:
                    can_edge = self._parse_edge(el)
                    # If the product of the first node is not the analyzed or
                    # if the product of either nodes is in rules skip that edge
                    if (can_edge[0].startswith('//') or
                        (any(r in can_edge[0] for r in self.rules) or
                         any(r in can_edge[1] for r in self.rules))):
                        continue
                    can_edge[0] = self.nodes[can_edge[0]]['id']
                    if can_edge[1] in self.nodes:
                        can_edge[1] = self.nodes[can_edge[1]]['id']
                        self.can_graph['internalCalls'].append(can_edge)
                    else:
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
            'cha': self.nodes
        }
        with open(self.output, 'w') as fdr:
            json.dump(data, fdr)

    def canonicalize(self):
        self.parse_files()
        self.detect_functions()
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


    def _parse_node_declaration(self, node):
        _, _, path, _ = self._parse_node_string(node)
        path = canonicalize_path(path, self.product_regex)
        can_uri = self._get_uri(node)
        return can_uri, path

    def _parse_edge(self, edge):
        node1 = self._get_uri(edge[0])
        node2 = self._get_uri(edge[1])
        return [node1, node2]

    def _get_uri(self, node):
        product, namespace, function = self._parse_node(node)
        if (product not in self.dependencies_lookup and
                product not in self.rules and
                product != self.product and
                product not in self.environment_deps and
                product != UNDEFINED_PRODUCT):
            self.logger.warning(
                "Warning: %s not found in dependencies", product
            )
            self.environment_deps.add(product)
        return self._uri_generator(product, namespace, function)

    def _uri_generator(self, product, namespace, function):
        forge_product_version = ''
        if product != self.product:
            forge_product_version += '//' + product
        return '{}/{}/{}'.format(forge_product_version, namespace, function)

    def _parse_node_string(self, node):
        is_defined = True
        if self.defined_bit:
            scope, is_defined, path, entity = node.split(':')
            is_defined = False if is_defined == '0' else True
        else:
            scope, path, entity = node.split(':')
        return scope, is_defined, path, entity

    def _parse_node(self, node):
        scope, is_defined, path, entity = self._parse_node_string(node)
        product = self._find_product(path, entity)
        if scope == 'static':
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
        return product, namespace, function

    def _find_product(self, path, function):
        # Check if function is in the functions found in shared libraries
        if function in self.functions:
            return self.functions[function]
        # Check if path is in paths_lookup
        if path in self.paths_lookup:
            stdout, status = self.paths_lookup[path]
            if status == 0:
                return stdout
        # Check if the callable belongs to the analyzed product
        if re.match(r'' + self.product_regex, path):
            self.logger.debug("product match: %s", path)
            return self.product
        # Detect product by examining the path
        if path not in self.paths_lookup:
            stdout, status = find_product(path)
            self.paths_lookup[path] = (stdout, status)
            if status == 0:
                return stdout
        # Check if it is a product from custom deps based on the path
        if self.custom_deps is not None:
            product = check_custom_deps(path, self.custom_deps)
            if product is not None:
                return product
        if not path.startswith('/'):
            return self.product
        self.logger.warning(
                "Warning: UNDEFINED match: path %s, function %s", path, function
        )
        return UNDEFINED_PRODUCT

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
                        default=None,
                        help='regex (of prefix) to match product\'s files')
    parser.add_argument('-s', '--source',
                        default='', help='product\'s source')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='file to save the canonicalized call graph')
    parser.add_argument('-a', '--analyzer', default='',
                        help='Analyzer used to generate the call graphs')
    parser.add_argument('-R', '--release', choices=['buster', 'bullseye'],
                        help=('Debian Release. This option is used to get '
                              'the virtual packages of a release'))
    parser.add_argument('-d', '--defined-bit', dest='defined_bit',
                        action='store_true',
                        help=('Check for bit that declares if a function is '
                              'defined. In this case a node should have the '
                              'following format: '
                              'static|public:0|1:path:function_name'
                             )
                       )
    args = parser.parse_args()
    virtuals = {}
    if args.release:
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
            defined_bit=args.defined_bit,
            virtuals=virtuals,
            release=release
    )
    can.canonicalize()


if __name__ == "__main__":
    main()
