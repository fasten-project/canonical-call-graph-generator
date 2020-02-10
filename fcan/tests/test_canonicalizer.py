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


class find_product_mock(Mock):
    def __call__(self, *args, **kwargs):
        path = args[0]
        if path.startswith('/build/'):
            return '', 1
        elif path.startswith('/usr/local/include/cscout/'):
            return '', 1
        elif path.startswith('/usr/include/debian-installer/'):
            return 'libdebian-installer4-dev:1.53 amd64'.encode(), 0
        elif path.startswith('/usr/include/cdebconf/'):
            return 'libdebconfclient0-dev'.encode(), 0
        elif path.startswith('/usr/include/stdlib.h'):
            return 'libc6-dev'.encode(), 0
        return '', 1


class parse_deb_file_mock(Mock):
    def __call__(self, *args, **kwargs):
        filename = args[0]
        if filename == './tests/data/anna-1.58/anna_1.58_amd64.udeb':
            return {
                'Package': 'anna',
                'Version': '1.58',
                'Architecture': 'amd64',
                'Depends': 'libc6-udeb (>= 2.24), libdebconfclient0-udeb, libdebian-installer4-udeb (>= 0.110), cdebconf-udeb'
            }
        if filename == './tests/data/anna-1.71-defined/anna_1.71_amd64.udeb':
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


def get_canonicalizer(package):
    directory = get_directory(package)
    return C_Canonicalizer(directory, console_logging=False)


def get_canonicalizer_with_custom_deps(package, deps, parse=False,
                                       defined_bit=False):
    directory = get_directory(package)
    custom_deps = get_directory(deps)
    can = C_Canonicalizer(directory, console_logging=False,
                          custom_deps=custom_deps, defined_bit=defined_bit)
    if parse:
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


# anna-1.58
can_graph = [
    ('/C/main()', '//libc6-dev/C/getenv()'),
    ('/./anna.c;foo()', '//libc6-dev/C/getenv()'),
    ('/src/anna.c;main()', '//libc6-dev/C/getenv()'),
    ('/C/set_retriever()',
     '//libdebconfclient0-dev/%2Fusr%2Finclude%2Fcdebconf/' +
     'debconfclient.h;debconf_set()'),
    ('/C/main()', '//libdebian-installer4-dev/C/' +
     'di_system_package_check_subarchitecture()'),
    ('/C/main()', '//libdebian-installer4-dev/' +
     '%2Fusr%2Finclude%2Fdebian-installer%2Fsystem/packages.h;' +
     'di_system_packages_status_read_file()')
]


# anna-1.71
can_graph2 = [
    ('/C/set_retriever()', '//libdebconfclient0-dev/%2Fusr%2Finclude%2F' +
     'cdebconf/debconfclient.h;debconf_set()'),
    ('/C/set_retriever()', '/C/xasprintf()'),
    ('/C/retriever_retrieve()', '//UNDEFINED/C/free()'),
    ('/C/retriever_retrieve()', '/C/get_retriever()'),
    ('/C/is_installed()', '//UNDEFINED/C/di_packages_get_package()')
]


def test_init():
    # missing all files
    with pytest.raises(CanonicalizationError):
        assert get_canonicalizer('package1')
    # missing .dsc file
    with pytest.raises(CanonicalizationError):
        assert get_canonicalizer('package3')


@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_parse_files(mock_parse_deb_file):
    can = get_canonicalizer('anna-1.58')
    can.parse_files()
    assert can.product == 'anna', "Should be anna"
    assert can.version == '1.58', "Should be 1.58"
    assert can.timestamp == '1488709580', "Should be 1488709580"
    for dep in dependencies:
        assert dep in can.dependencies


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_gen_can_cgraph(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer('anna-1.58')
    can.parse_files()
    can.gen_can_cgraph()
    assert can_graph == can.can_graph


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_gen_can_cgraph_defined(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps(
        'anna-1.71-defined', 'custom_deps.json', defined_bit=True
    )
    can.parse_files()
    can.gen_can_cgraph()
    assert can_graph2 == can.can_graph


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_save(mock_find_product, mock_parse_deb_file):
    directory = get_directory('anna-1.58')
    filename = directory + '/' + 'can_cgraph.json'
    can = get_canonicalizer('anna-1.58')
    can.parse_files()
    can.gen_can_cgraph()
    can.save()
    with open(filename, 'r') as f:
        res = json.load(f)
    final_dependencies = copy.deepcopy(dependencies)
    environment_deps = [{"architectures": "", "constraints": "",
                         "forge": "debian", "product": "libc6-dev"}]
    for dep in final_dependencies:
        assert dep in res['depset']
    assert environment_deps[0] in res['environment_depset']
    for node in can_graph:
        assert list(node) in res['graph']
    assert res['product'] == 'anna'
    assert res['version'] == '1.58'
    assert res['forge'] == 'debian'
    assert res['timestamp'] == '1488709580'
    os.remove(filename)


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_canonicalize(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    can.canonicalize()
    directory = get_directory('anna-1.58')
    filename = directory + '/' + 'can_cgraph.json'
    with open(filename, 'r') as f:
        res = json.load(f)
    final_dependencies = copy.deepcopy(dependencies)
    final_dependencies.append({'product': "my_dep", 'forge': "github",
                               'constraints': "", 'architecture': ""})
    environment_deps = [{"architectures": "", "constraints": "",
                         "forge": "debian", "product": "libc6-dev"}]
    final_can_graph = copy.deepcopy(can_graph)
    final_can_graph.append(('/C/main()', '//my_dep/C/sum()'))
    for dep in final_dependencies:
        assert dep in res['depset']
    assert environment_deps[0] in res['environment_depset']
    for node in final_can_graph:
        assert list(node) in res['graph']
    assert res['product'] == 'anna'
    assert res['version'] == '1.58'
    assert res['forge'] == 'debian'
    assert res['timestamp'] == '1488709580'
    os.remove(filename)


@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_add_environment_dependenies(mock_parse_deb_file):
    can = get_canonicalizer('anna-1.58')
    can.parse_files()
    can.environment_deps.add('dep')
    environment_deps = can._get_environment_dependenies()
    temp = {'architectures': '', 'constraints': '',
            'forge': 'debian', 'product': 'dep'}
    assert environment_deps[0] == temp


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_find_product(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    can.parse_files()
    # Test 1
    path1 = '/build/anna-xjzj1e/anna-1.58/retriever.c'
    assert can._find_product(path1) == 'anna'
    # Test 2
    path2 = '/usr/local/include/cscout/csmake-pre-defs.h'
    assert can._find_product(path2) == 'CScout'
    # Test 3
    path3 = '/usr/include/debian-installer/exec.h'
    assert can._find_product(path3) == 'libdebian-installer4-dev'
    # Test 4
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json',
                                             True)
    path3 = '/usr/include/debian-installer/exec.h'
    assert can._find_product(path3) == 'libdebian-installer4-dev'
    path4 = '/usr/local/include/my_dep/utils.h'
    assert can._find_product(path4) == 'my_dep'


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_parse_node(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    can.parse_files()
    # Test 1
    node1 = 'public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever'
    res1 = ('anna', 'C', 'set_retriever()')
    assert can._parse_node(node1) == res1
    # Test 2
    node2 = 'static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    res2 = ('CScout', '%2Fusr%2Flocal%2Finclude%2Fcscout',
            'csmake-pre-defs.h;__attribute__()')
    assert can._parse_node(node2) == res2
    # Test 3
    node3 = 'static:/usr/include/cdebconf/debconfclient.h:debconf_set'
    res3 = ('libdebconfclient0-dev', '%2Fusr%2Finclude%2Fcdebconf',
            'debconfclient.h;debconf_set()')
    assert can._parse_node(node3) == res3


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_parse_node_defined(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps(
        'anna-1.71-defined', 'custom_deps.json', defined_bit=True
    )
    can.parse_files()
    # Test 1
    node1 = 'public:1:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever'
    res1 = ('anna', 'C', 'set_retriever()')
    assert can._parse_node(node1) == res1
    # Test 2
    node2 = 'static:1:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    res2 = ('CScout', '%2Fusr%2Flocal%2Finclude%2Fcscout',
            'csmake-pre-defs.h;__attribute__()')
    assert can._parse_node(node2) == res2
    # Test 3
    node3 = 'static:1:/usr/include/cdebconf/debconfclient.h:debconf_set'
    res3 = ('libdebconfclient0-dev', '%2Fusr%2Finclude%2Fcdebconf',
            'debconfclient.h;debconf_set()')
    assert can._parse_node(node3) == res3
    # Test 4
    node4 = 'public:0:/usr/include/stdlib.h:free'
    res4 = ('UNDEFINED', 'C', 'free()')
    assert can._parse_node(node4) == res4
    # Test 5
    node5 = 'public:0:/usr/include/debian-installer/packages.h:di_packages_get_package'
    res5 = ('UNDEFINED', 'C', 'di_packages_get_package()')
    assert can._parse_node(node5) == res5


@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_uri_generator(mock_parse_deb_file):
    can = get_canonicalizer('anna-1.58')
    can.parse_files()
    # Test 1
    node1 = ('anna', 'C', 'set_retriever()')
    res1 = '/C/set_retriever()'
    assert can._uri_generator(node1[0], node1[1], node1[2]) == res1
    # Test 2
    node2 = ('libdebconfclient0-dev', '%2Fusr%2Finclude%2Fcdebconf',
             'debconfclient.h;debconf_set()')
    res2 = '//libdebconfclient0-dev/%2Fusr%2Finclude%2Fcdebconf/' +\
        'debconfclient.h;debconf_set()'
    assert can._uri_generator(node2[0], node2[1], node2[2]) == res2


@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_uri_generator(mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps(
        'anna-1.71-defined', 'custom_deps.json', defined_bit=True
    )
    can.parse_files()
    # Test 1
    node1 = ('UNDEFINED', 'C', 'free()')
    res1 = '//UNDEFINED/C/free()'
    assert can._uri_generator(node1[0], node1[1], node1[2]) == res1
    # Test 2
    node2 = ('UNDEFINED', 'C', 'di_packages_get_package()')
    res2 = '//UNDEFINED/C/di_packages_get_package()'
    assert can._uri_generator(node2[0], node2[1], node2[2]) == res2


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_get_uri(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    can.parse_files()
    # Test 1
    node1 = 'public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever'
    res1 = '/C/set_retriever()'
    assert can._get_uri(node1) == res1
    # Test 2
    node2 = 'static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    res2 = '//CScout/%2Fusr%2Flocal%2Finclude%2Fcscout/' + \
        'csmake-pre-defs.h;__attribute__()'
    assert can._get_uri(node2) == res2
    # Test 3
    node3 = 'static:/usr/include/cdebconf/debconfclient.h:debconf_set'
    res3 = '//libdebconfclient0-dev/%2Fusr%2Finclude%2Fcdebconf/' +\
        'debconfclient.h;debconf_set()'
    assert can._get_uri(node3) == res3
    # Test 4
    node4 = 'static:/usr/include/random_proj/utils.h:rand'
    res4 = '//NULL/%2Fusr%2Finclude%2Frandom_proj/utils.h;rand()'
    assert can._get_uri(node4) == res4
    # Test 5
    assert 'libc6-dev' not in can.environment_deps
    node5 = 'public:/usr/include/stdlib.h:getenv'
    res5 = '//libc6-dev/C/getenv()'
    assert can._get_uri(node5) == res5
    assert 'libc6-dev' in can.environment_deps
    # Test 6
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json',
                                             True)
    my_dep = {'product': "my_dep", 'forge': "github", 'constraints': "",
              'architecture': ""}
    node6 = 'public:/usr/local/include/my_dep/utils.h:sum'
    res6 = '//my_dep/C/sum()'
    assert can._get_uri(node6) == res6
    assert my_dep in can.dependencies


@patch("fcan.fcan.find_product", new_callable=find_product_mock)
@patch("fcan.fcan.parse_deb_file", new_callable=parse_deb_file_mock)
def test_parse_edge(mock_find_product, mock_parse_deb_file):
    can = get_canonicalizer_with_custom_deps('anna-1.58', 'custom_deps.json')
    can.parse_files()
    edge = [
        'public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever',
        'static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__'
    ]
    nodes = (
        '/C/set_retriever()',
        '//CScout/%2Fusr%2Flocal%2Finclude%2Fcscout/' +
        'csmake-pre-defs.h;__attribute__()'
    )
    assert can._parse_edge(edge) == nodes
