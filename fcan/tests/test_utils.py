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
from shutil import which
from mock import patch
from mock import Mock
from fcan.fcan import safe_split, extract_text, parse_dependency,\
        check_custom_deps, use_mvn_spec, parse_changelog,\
        convert_debian_time_to_unix, canonicalize_path, run_command,\
        parse_dsc_file, parse_deb_file, canonicalize_binary_name,\
        find_product, find_shared_libs_products, find_static_libraries_products


def get_directory(filename):
    directory = '{}/{}/{}/{}'.format(
        os.path.curdir, 'tests', 'data', filename
    )
    return directory


def check_command_exist(cmd):
    return which(cmd) is not None


def read_return(path, parse_stdout):
    with open(path, 'r') as f:
        res = f.read()
        res = res.encode("utf-8")
        if parse_stdout:
            return res.decode("utf-8").split("\n"), 0
        return res, 0


class run_command_mock(Mock):
    def __call__(self, *args, **kwargs):
        data = get_directory('mocked_data')
        arguments = args[0]
        parse_stdout = True
        if len(args) == 2:
            parse_stdout = args[1]
        if arguments[0] == 'dpkg':
            if arguments[1] == '-S':
                base = '{}/dpkg/S/'.format(data)
                if arguments[2] == '/lib/x86_64-linux-gnu/libc.so.6':
                    filepath = base + 'x86_libc.so.6'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == 'libc.so.6':
                    filepath = base + 'libc.so.6'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == 'libdebconfclient.so.0':
                    filepath = base + 'libdebconfclient.so.0'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == 'libdebian-installer.so.4':
                    filepath = base + 'libdebian-installer.so.4'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == '/lib64/ld-linux-x86-64.so.2':
                    filepath = base + 'ld-linux-x86-64.so.2'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == '/usr/lib/x86_64-linux-gnu/libdebian-installer.a':
                    filepath = base + 'libdebian-installer.a'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == '/usr/lib/gcc/x86_64-linux-gnu/9/libgcc.a':
                    filepath = base + 'libgcc.a'
                    return read_return(filepath, parse_stdout)
                elif arguments[2] == '/usr/lib/x86_64-linux-gnu/libc.a':
                    filepath = base + 'libc.a'
                    return read_return(filepath, parse_stdout)
            elif arguments[1] == '-I':
                base = '{}/dpkg/I/'.format(data)
                if arguments[2].endswith('mydeb.udeb'):
                    filepath = base + 'mydeb.udeb'
                    return read_return(filepath, parse_stdout)
        elif arguments[0] == 'ldd':
            if arguments[1] == '-d':
                base = '{}/ldd/d/'.format(data)
                if arguments[2] == 'anna':
                    filepath = base + 'anna'
                    return read_return(filepath, parse_stdout)


def test_safe_split():
    assert safe_split('foo, bar') == ['foo', 'bar'],\
        "Should return ['foo', 'bar']"
    assert safe_split('foo, (bar, baz)') == ['foo', '(bar, baz)'],\
        "Should return ['foo', '(bar, baz)']"
    assert safe_split('foo, (bar, baz)') == ['foo', '(bar, baz)'],\
        "Should return ['foo', '(bar, baz)']"
    assert safe_split('foo, (bar, baz)') == ['foo', '(bar, baz)'],\
        "Should return ['foo', '(bar, baz)']"
    assert safe_split('foo, bak [bar, baz]') == ['foo', 'bak [bar, baz]'],\
        "Should return ['foo', 'bak [bar, baz]']"
    assert safe_split('foo, bar [foo, baz], baz (foo, bar)') == \
        ['foo', 'bar [foo, baz]', 'baz (foo, bar)'],\
        "Should return ['foo', 'bar [foo, baz]', 'baz (foo, bar)']"
    assert safe_split('foo bar') == ['foo bar'],\
        "Should return ['foo bar']"
    assert safe_split('foo bar', sep=' ') == ['foo', 'bar'],\
        "Should return ['foo', 'bar']"


def test_extract_text():
    assert extract_text("Hello (world)") == ("world", "Hello"),\
        "Should return ('world', 'Hello')"
    assert extract_text("package [amd64,arm]", ('[', ']')) == \
        ("amd64,arm", "package"),\
        "Should return ('amd64,arm', 'package')"
    assert extract_text("Hello world") == ("", "Hello world"),\
        "Should return ('', 'Hello world')"


simple_product = {'architectures': [], 'constraints': "[9,)",
                  'forge': "debian", 'product': "debhelper",
                  'dependency_type': "Depends", 'is_virtual': False,
                  'alternatives': []}
complex_product = {
        'architectures': [],
        'constraints': "",
        'forge': "",
        'product': "libdebian-installer4-dev-alternatives",
        'is_virtual': False,
        'dependency_type': "Alternatives",
        'alternatives': [{
            'architectures': ["amd64"],
            'constraints': "",
            'forge': "debian",
            'product': "libdebian-installer4-dev",
            'is_virtual': False,
            'dependency_type': "Depends",
            'alternatives': []
         },
         {
            'architectures': [],
            'constraints': "",
            'dependency_type': "Depends",
            'is_virtual': False,
            'forge': "debian",
            'product': "libdebconfclient-dev",
            'alternatives': []
         }]
}


def test_parse_dependency():
    assert parse_dependency("debhelper (>= 9)", "debian", "Depends") ==\
            simple_product
    assert parse_dependency(
        "libdebian-installer4-dev [amd64] | libdebconfclient-dev",
        "debian", "Depends") == complex_product


def test_run_command():
    assert run_command(['echo', 'hello'], False)[0] == b'hello\n'
    assert run_command(['echo', 'hello'])[0] == ['hello', '']
    assert run_command(['echo', 'hello'])[1] == 0
    assert run_command(['echo111', 'hello'])[0] == ''
    assert run_command(['echo111', 'hello'])[1] == -1


@patch("fcan.fcan.run_command", new_callable=run_command_mock)
def test_find_product(mock_run_command):
    paths = [
        '/lib/x86_64-linux-gnu/libc.so.6',
        'libc.so.6'
    ]
    results = [
        ('libc6', 0),
        ('libc6', 0)
    ]
    for p, r in zip(paths, results):
        assert find_product(p) == r


def test_check_custom_deps():
    custom_deps = {
                "my_dep": {
                    "forge": "github",
                    "constraints": "",
                    "architecture": "",
                    "regex": [
                        "^/usr/local/include/my_dep/.*"
                    ]
                }
    }
    path = "/usr/local/include/my_dep/utils.h"
    assert check_custom_deps(path, custom_deps) == 'my_dep'
    assert check_custom_deps('/random/path', custom_deps) is None


def test_use_mvn_spec():
    assert use_mvn_spec("= 1.0") == "[1.0]", "Should return [1.0]"
    assert use_mvn_spec("<= 1.0") == "(,1.0]", "Should return (,1.0]"
    assert use_mvn_spec("<< 1.0") == "(,1.0)", "Should return (,1.0)"
    assert use_mvn_spec(">= 1.0") == "[1.0,)", "Should return [1.0,)"
    assert use_mvn_spec(">> 1.0") == "(1.0,)", "Should return (1.0,)"
    assert use_mvn_spec("") == "", "Should return ''"


def test_parse_changelog():
    package3 = get_directory('package3')
    anna = get_directory('anna-1.58')
    assert parse_changelog(package3 + '/changelog', '1.58') is None
    assert (parse_changelog(anna + '/changelog', '1.58') ==
            'Sun, 05 Mar 2017 12:26:20 +0100')
    assert (parse_changelog(anna + '/changelog', '1.57') ==
            'Mon, 13 Feb 2017 07:08:47 +0100')


anna_dsc_res = {
    'Build-Depends': "debhelper (>= 9), dpkg-dev (>= 1.15.7), libdebconfclient0-dev (>= 0.46), libdebian-installer4-dev (>= 0.109)"
}


def test_parse_dsc_file():
    anna_dsc = get_directory('anna-1.71-defined') + '/anna_1.71.dsc'
    assert parse_dsc_file(anna_dsc) == anna_dsc_res


anna_deb_res = {
    'Package': "anna",
    'Version': "1.71",
    'Architecture': "amd64",
    'Depends': "libc6-udeb (>= 2.28), libdebconfclient0-udeb, libdebian-installer4-udeb (>= 0.119), cdebconf-udeb"
}


@patch("fcan.fcan.run_command", new_callable=run_command_mock)
def test_parse_deb_file_mock_run_command(mock_run_command):
    anna_deb = get_directory('anna-1.71-defined') + '/mydeb.udeb'
    assert parse_deb_file(anna_deb) == anna_deb_res


def test_parse_deb_file():
    if check_command_exist('dpkg'):
        anna_deb = get_directory('anna-1.71-defined') + '/mydeb.udeb'
        assert parse_deb_file(anna_deb) == anna_deb_res


def test_convert_debian_time_to_unix():
    d1 = "Sun, 05 Mar 2017 12:26:20 +0100"
    epoch1 = "1488709580"
    assert convert_debian_time_to_unix(d1) == epoch1


def test_canonicalize_path():
    paths = [
        './libmisc/walk_tree.c',
        '/usr/include/cdebconf/debconfclient.h',
        '/build/anna-oYTzHL/anna-1.71/anna.c',
        '/build/anna-oYTzHL/anna-1.71/src/anna.c',
        '/build/mlocate-OLrxYu/mlocate-0.26/build/../src/conf.c',
        '/build/mlocate-OLrxYu/mlocate-0.26/build/gnulib/lib/../../../gnulib/lib/mbuiter.h',
        './build/gnulib/lib/../../../gnulib/lib/mbuiter.h',
        'build/gnulib/lib/../../../gnulib/lib/mbuiter.h'
    ]
    results = [
        'libmisc/walk_tree.c',
        '/usr/include/cdebconf/debconfclient.h',
        'anna.c',
        'src/anna.c',
        'src/conf.c',
        'gnulib/lib/mbuiter.h',
        'gnulib/lib/mbuiter.h',
        'gnulib/lib/mbuiter.h'
    ]
    for p, r in zip(paths, results):
        assert canonicalize_path(p) == r


def test_canonicalize_binary_name():
    binaries = [
        '/lib/x86_64-linux-gnu/libc.so.6',
        '/lib/x86_64-linux-gnu/libc.a',
        '/lib/x86_64-linux-gnu/libc.so',
        'libc.so',
        'libc.a',
        'libc.a.00',
        'libc.so.0.0.1',
        'libc.so.0.0.0a'
    ]
    results = [
        'libc.so',
        'libc.a',
        'libc.so',
        'libc.so',
        'libc.a',
        'libc.a',
        'libc.so',
        'libc.so'
    ]
    for b, r in zip(binaries, results):
        assert canonicalize_binary_name(b) == r


@patch("fcan.fcan.run_command", new_callable=run_command_mock)
def test_find_shared_libs_products(mock_run_command):
    res = [
        ('/lib/x86_64-linux-gnu/libdebconfclient.so.0', 'libdebconfclient0'),
        ('/lib/x86_64-linux-gnu/libdebian-installer.so.4', 'libdebian-installer4'),
        ('/lib/x86_64-linux-gnu/libc.so.6', 'libc6'),
        ('/lib64/ld-linux-x86-64.so.2', 'libc6')
    ]
    assert set(find_shared_libs_products('anna')) == set(res)


@patch("fcan.fcan.run_command", new_callable=run_command_mock)
def test_find_static_libraries_products(mock_run_command):
    cs = get_directory('anna-1.71-defined') + '/anna.cs'
    reg = '^/build/anna/anna-1.71.*'
    product = 'anna'
    res = [
        ('/usr/lib/x86_64-linux-gnu/libc.a', 'libc6-dev'),
        ('/usr/lib/x86_64-linux-gnu/libdebian-installer.a', 'libdebian-installer4-dev'),
        ('/usr/lib/gcc/x86_64-linux-gnu/9/libgcc.a', 'libgcc-9-dev')
    ]
    assert set(find_static_libraries_products(cs, product, reg)) == set(res)
