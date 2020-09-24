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
import os
import json
import copy
import pytest
from mock import patch
from mock import Mock
from fcan.fcan import C_Canonicalizer
from fcan.fcan import CanonicalizationError


LIBC6_DEV = (
    '/usr/include/x86_64-linux-gnu/sys/stat.h',
    '/usr/include/x86_64-linux-gnu/bits/fcntl2.h',
    '/usr/include/stdio.h',
    '/usr/include/x86_64-linux-gnu/bits/stdio2.h',
    '/usr/include/x86_64-linux-gnu/bits/unistd.h',
    '/usr/include/x86_64-linux-gnu/sys/stat.h',
    '/usr/include/fcntl.h',
    '/usr/include/endian.h'
)


class find_product_mock(Mock):
    def __call__(self, *args, **kwargs):
        path = args[0]
        if path.startswith('/build/'):
            return '', 1
        elif path.startswith('/usr/local/include/cscout/'):
            return '', 1
        elif path.startswith('/usr/include/debian-installer/'):
            return 'libdebian-installer4-dev', 0
        elif path.startswith('/usr/include/cdebconf/'):
            return 'libdebconfclient0-dev', 0
        elif any(path.startswith(x) for x in LIBC6_DEV):
            return 'libc6-dev', 0
        return '', 1


class parse_deb_file_mock(Mock):
    def __call__(self, *args, **kwargs):
        filename = args[0]
        if filename == './tests/data/anna-1.58/mydeb.udeb':
            return {
                'Package': 'anna',
                'Version': '1.58',
                'Architecture': 'amd64',
                'Depends': 'libc6-udeb (>= 2.24), libdebconfclient0-udeb, libdebian-installer4-udeb (>= 0.110), cdebconf-udeb'
            }
        if filename == './tests/data/anna-1.71-defined/mydeb.udeb':
            return {
                'Package': 'anna',
                'Version': '1.71',
                'Architecture': 'amd64',
                'Depends': 'libc6-udeb (>= 2.24), libdebconfclient0-udeb, libdebian-installer4-udeb (>= 0.110), cdebconf-udeb'
            }
        return {}


def get_directory(filename):
    directory = '{}/{}/{}/{}'.format(
        os.path.curdir, 'tests', 'data', filename
    )
    return directory


def get_canonicalizer(package, deb='', dsc='', output=None):
    directory = get_directory(package)
    deb = '{}/{}'.format(directory, deb)
    dsc = '{}/{}'.format(directory, dsc)
    changelog = '{}/changelog'.format(directory)
    binaries = '{}/binaries'.format(directory)
    return C_Canonicalizer(
            deb, dsc, changelog, binaries,
            console_logging=False, output=output
    )


def get_canonicalizer_with_custom_deps(package, deps, deb, dsc, cparse=False,
                                       output=None, defined_bit=False):
    directory = get_directory(package)
    deb = '{}/{}'.format(directory, deb)
    dsc = '{}/{}'.format(directory, dsc)
    changelog = '{}/changelog'.format(directory)
    binaries = '{}/binaries'.format(directory)
    custom_deps = get_directory(deps)
    can = C_Canonicalizer(
            deb, dsc, changelog, binaries,
            console_logging=False, output=output,
            custom_deps=custom_deps
    )
    if cparse:
        can.parse_files()
    return can


dependencies = [{'forge': 'debian', 'product': 'libdebian-installer4-udeb',
                 'constraints': '[0.110,)', 'architectures': ''},
                {'forge': 'debian', 'product': 'libdebconfclient0-udeb',
                 'constraints': '', 'architectures': ''},
                {'forge': 'debian', 'product': 'libc6-udeb',
                 'constraints': '[2.24,)', 'architectures': ''},
                {'forge': 'debian', 'product': 'cdebconf-udeb',
                 'constraints': '', 'architectures': ''}]

dependencies = [{'alternatives': [],
                 'architectures': [],
                 'constraints': '',
                 'dependency_type': 'Depends',
                 'forge': 'debian',
                 'is_virtual': False,
                 'product': 'libdebconfclient0'},
                {'alternatives': [],
                 'architectures': [],
                 'constraints': '[2.24,)',
                 'dependency_type': 'Depends',
                 'forge': 'debian',
                 'is_virtual': False,
                 'product': 'libc6'},
                {'alternatives': [],
                 'architectures': [],
                 'constraints': '[0.110,)',
                 'dependency_type': 'Depends',
                 'forge': 'debian',
                 'is_virtual': False,
                 'product': 'libdebian-installer4'},
                {'alternatives': [],
                 'architectures': [],
                 'constraints': '',
                 'dependency_type': 'Depends',
                 'forge': 'debian',
                 'is_virtual': False,
                 'product': 'cdebconf'}
                ]

build_dependencies = [{'alternatives': [],
                       'architectures': [],
                       'constraints': '[9,)',
                       'dependency_type': 'Build-Depends',
                       'forge': 'debian',
                       'is_virtual': False,
                       'product': 'debhelper'},
                      {'alternatives': [],
                       'architectures': [],
                       'constraints': '[0.46,)',
                       'dependency_type': 'Build-Depends',
                       'forge': 'debian',
                       'is_virtual': False,
                       'product': 'libdebconfclient0-dev'},
                      {'alternatives': [],
                       'architectures': [],
                       'constraints': '[1.15.7,)',
                       'dependency_type': 'Build-Depends',
                       'forge': 'debian',
                       'is_virtual': False,
                       'product': 'dpkg-dev'},
                      {'alternatives': [],
                       'architectures': [],
                       'constraints': '[0.109,)',
                       'dependency_type': 'Build-Depends',
                       'forge': 'debian',
                       'is_virtual': False,
                       'product': 'libdebian-installer4-dev'}]


# Functions
with open('./tests/data/anna171functions.json', 'r') as json_file:
    functions = json.load(json_file)

# anna-1.71
can_graph = {
    'externalCalls': [[4, 12], [11, 13], [10, 17]],
    'internalCalls': [[2, 1], [5, 3], [11, 6], [11, 8], [11, 9]],
    'resolvedCalls': [[11, 14], [11, 15], [11, 16]]
}


def test_init():
    # missing all files
    with pytest.raises(CanonicalizationError):
        assert get_canonicalizer('package1')
    # missing .dsc file
    with pytest.raises(CanonicalizationError):
        assert get_canonicalizer('package3')


@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_parse_files(mock_parse_deb_file):
    can = get_canonicalizer('anna-1.71-defined', 'mydeb.udeb', 'anna_1.71.dsc')
    can.parse_files()
    assert can.product == 'anna', "Should be anna"
    assert can.version == '1.71', "Should be 1.71"
    assert can.timestamp == '1551808677', "Should be 1551808677"
    for dep in dependencies:
        assert dep in can.dependencies
    for dep in build_dependencies:
        assert dep in can.build_dependencies


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_gen_can_functions(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer('anna-1.71-defined', 'mydeb.udeb', 'anna_1.71.dsc')
    can.parse_files()
    can.gen_can_cgraph()
    assert functions == can.functions


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_gen_can_cgraph(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer('anna-1.71-defined', 'mydeb.udeb', 'anna_1.71.dsc')
    can.parse_files()
    can.gen_can_cgraph()
    assert can_graph == can.can_graph


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_save(mock_find_product, mock_parse_deb_file):
    output = './tests/data/anna-1.71-defined/output.json'
    can = get_canonicalizer(
        'anna-1.71-defined', 'mydeb.udeb', 'anna_1.71.dsc', output=output)
    can.parse_files()
    can.gen_can_cgraph()
    can.save()
    with open(output, 'r') as f:
        res = json.load(f)
    with open('./tests/data/anna-1.71-defined/cgraph.json', 'r') as f:
        test = json.load(f)
    assert res['product'] == "anna"
    assert res['version'] == "1.71"
    assert res['release'] == ""
    assert res['generator'] == ""
    assert res['source'] == ""
    assert res['forge'] == "debian"
    assert res['architecture'] == "amd64"
    assert res['functions'] == test['functions']
    assert res['graph'] == test['graph']
    os.remove(output)


@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_add_environment_dependenies(mock_parse_deb_file):
    can = get_canonicalizer('anna-1.71-defined', 'mydeb.udeb', 'anna_1.71.dsc')
    can.parse_files()
    can.environment_deps.add('dep')
    environment_deps = can._get_environment_dependenies()
    temp = {'architectures': '', 'constraints': '',
            'forge': 'debian', 'product': 'dep', 'alternatives': [],
            'dependency_type': '', 'is_virtual': False}
    print(environment_deps)
    assert temp in environment_deps


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_find_product(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer('anna-1.71-defined', 'mydeb.udeb', 'anna_1.71.dsc')
    can.parse_files()
    can.current_binary = "anna"
    # Test 1
    path1 = '/build/anna-xjzj1e/anna-1.71/retriever.c'
    function1 = 'retrieve'
    assert can._find_product(path1, function1) == 'anna'
    # Test 2
    path2 = '/usr/local/include/cscout/csmake-pre-defs.h'
    function2 = 'foo'
    assert can._find_product(path2, function2) == 'UNDEFINED'
    # Test 3
    path3 = '/usr/include/debian-installer/exec.h'
    function3 = 'exec'
    assert can._find_product(path3, function3) == 'libdebian-installer4-dev'
    # With Custom Dependencies
    can = get_canonicalizer_with_custom_deps(
        'anna-1.71-defined', 'custom_deps.json',
        'mydeb.udeb', 'anna_1.71.dsc', True
    )
    can.parse_files()
    can.current_binary = "anna"
    # Test 4
    path4 = '/usr/include/debian-installer/exec.h'
    function4 = 'exec'
    assert can._find_product(path4, function4) == 'libdebian-installer4-dev'
    # Test 5
    path5 = '/usr/local/include/my_dep/utils.h'
    function5 = 'bar'
    # Test 6
    assert can._find_product(path5, function5) == 'my_dep'
    path6 = '/usr/local/include/cscout/csmake-pre-defs.h'
    function6 = 'foo'
    assert can._find_product(path6, function6) == 'CScout'


#  @patch("fcan.fcan.find_product", new_callable=find_product_mock)
#  @patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
#  def test_parse_node(mock_find_product, mock_parse_deb_file):
    #  can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    #  can.parse_files()
    #  # Test 1
    #  node1 = 'public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever'
    #  res1 = ('anna', 'C', 'set_retriever()')
    #  assert can._parse_node(node1) == res1
    #  # Test 2
    #  node2 = 'static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    #  res2 = ('CScout', '%2Fusr%2Flocal%2Finclude%2Fcscout',
            #  'csmake-pre-defs.h;__attribute__()')
    #  assert can._parse_node(node2) == res2
    #  # Test 3
    #  node3 = 'static:/usr/include/cdebconf/debconfclient.h:debconf_set'
    #  res3 = ('libdebconfclient0-dev', '%2Fusr%2Finclude%2Fcdebconf',
            #  'debconfclient.h;debconf_set()')
    #  assert can._parse_node(node3) == res3


#  @patch("fcan.fcan.find_product", new_callable=find_product_mock)
#  @patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
#  def test_parse_node_defined(mock_find_product, mock_parse_deb_file):
    #  can = get_canonicalizer_with_custom_deps(
        #  'anna-1.71-defined', 'custom_deps.json', defined_bit=True
    #  )
    #  can.parse_files()
    #  # Test 1
    #  node1 = 'public:1:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever'
    #  res1 = ('anna', 'C', 'set_retriever()')
    #  assert can._parse_node(node1) == res1
    #  # Test 2
    #  node2 = 'static:1:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    #  res2 = ('CScout', '%2Fusr%2Flocal%2Finclude%2Fcscout',
            #  'csmake-pre-defs.h;__attribute__()')
    #  assert can._parse_node(node2) == res2
    #  # Test 3
    #  node3 = 'static:1:/usr/include/cdebconf/debconfclient.h:debconf_set'
    #  res3 = ('libdebconfclient0-dev', '%2Fusr%2Finclude%2Fcdebconf',
            #  'debconfclient.h;debconf_set()')
    #  assert can._parse_node(node3) == res3
    #  # Test 4
    #  node4 = 'public:0:/usr/include/stdlib.h:free'
    #  res4 = ('UNDEFINED', 'C', 'free()')
    #  assert can._parse_node(node4) == res4
    #  # Test 5
    #  node5 = 'public:0:/usr/include/debian-installer/packages.h:di_packages_get_package'
    #  res5 = ('UNDEFINED', 'C', 'di_packages_get_package()')
    #  assert can._parse_node(node5) == res5


#  @patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
#  def test_uri_generator(mock_parse_deb_file):
    #  can = get_canonicalizer_with_custom_deps(
        #  'anna-1.71-defined', 'custom_deps.json', defined_bit=True
    #  )
    #  can.parse_files()
    #  # Test 1
    #  node1 = ('UNDEFINED', 'C', 'free()')
    #  res1 = '//UNDEFINED/C/free()'
    #  assert can._uri_generator(node1[0], node1[1], node1[2]) == res1
    #  # Test 2
    #  node2 = ('UNDEFINED', 'C', 'di_packages_get_package()')
    #  res2 = '//UNDEFINED/C/di_packages_get_package()'
    #  assert can._uri_generator(node2[0], node2[1], node2[2]) == res2


#  @patch("fcan.fcan.find_product", new_callable=find_product_mock)
#  @patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
#  def test_get_uri(mock_find_product, mock_parse_deb_file):
    #  can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    #  can.parse_files()
    #  # Test 1
    #  node1 = 'public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever'
    #  res1 = '/C/set_retriever()'
    #  assert can._get_uri(node1) == res1
    #  # Test 2
    #  node2 = 'static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    #  res2 = '//CScout/%2Fusr%2Flocal%2Finclude%2Fcscout/' + \
        #  'csmake-pre-defs.h;__attribute__()'
    #  assert can._get_uri(node2) == res2
    #  # Test 3
    #  node3 = 'static:/usr/include/cdebconf/debconfclient.h:debconf_set'
    #  res3 = '//libdebconfclient0-dev/%2Fusr%2Finclude%2Fcdebconf/' +\
        #  'debconfclient.h;debconf_set()'
    #  assert can._get_uri(node3) == res3
    #  # Test 4
    #  node4 = 'static:/usr/include/random_proj/utils.h:rand'
    #  res4 = '//NULL/%2Fusr%2Finclude%2Frandom_proj/utils.h;rand()'
    #  assert can._get_uri(node4) == res4
    #  # Test 5
    #  assert 'libc6-dev' not in can.environment_deps
    #  node5 = 'public:/usr/include/stdlib.h:getenv'
    #  res5 = '//libc6-dev/C/getenv()'
    #  assert can._get_uri(node5) == res5
    #  assert 'libc6-dev' in can.environment_deps
    #  # Test 6
    #  can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json',
                                             #  True)
    #  my_dep = {'product': "my_dep", 'forge': "github", 'constraints': "",
              #  'architecture': ""}
    #  node6 = 'public:/usr/local/include/my_dep/utils.h:sum'
    #  res6 = '//my_dep/C/sum()'
    #  assert can._get_uri(node6) == res6
    #  assert my_dep in can.dependencies


#  @patch("fcan.fcan.find_product", new_callable=find_product_mock)
#  @patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
#  def test_parse_edge(mock_find_product, mock_parse_deb_file):
    #  can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    #  can.parse_files()
    #  edge = [
        #  'public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever',
        #  'static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    #  ]
    #  nodes = (
        #  '/C/set_retriever()',
        #  '//CScout/%2Fusr%2Flocal%2Finclude%2Fcscout/' +
        #  'csmake-pre-defs.h;__attribute__()'
    #  )
    #  assert can._parse_edge(edge) == nodes
