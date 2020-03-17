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
from mock import patch
from mock import Mock
from fcan.fcan import safe_split, extract_text, parse_dependency,\
        check_custom_deps, use_mvn_spec, parse_changelog,\
        convert_debian_time_to_unix, canonicalize_path, run_command,\
        find_shared_libs_util


def get_directory(filename):
    directory = '{}/{}/{}/{}'.format(
        os.path.curdir, 'tests', 'data', filename
    )
    return directory


class find_product_mock(Mock):
    def __call__(self, *args, **kwargs):
        path = args[0]
        if path == 'libdebconfclient.so.0':
            return 'libdebconfclient0', 0
        elif path == 'libdebian-installer.so.4':
            return 'libdebian-installer4', 0
        elif path == 'libc.so.6':
            return 'libc6', 0
        elif path == '/lib64/ld-linux-x86-64.so.2':
            return 'libc6', 0
        return '', 1


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


simple_product = {'architectures': "", 'constraints': "[9,)",
                  'forge': "debian", 'product': "debhelper"}
complex_product = {
        'architectures': "",
        'constraints': "",
        'forge': "debian",
        'product': "libdebconfclient-dev",
        'alternatives': [{
            'architectures': "amd64",
            'constraints': "",
            'forge': "debian",
            'product': "libdebian-installer4-dev"
         }]
}


def test_parse_dependency():
    assert parse_dependency("debhelper (>= 9)", "debian") == simple_product
    assert parse_dependency(
        "libdebian-installer4-dev [amd64] | libdebconfclient-dev",
        "debian") == complex_product


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


def test_convert_debian_time_to_unix():
    d1 = "Sun, 05 Mar 2017 12:26:20 +0100"
    epoch1 = "1488709580"
    assert convert_debian_time_to_unix(d1) == epoch1


def test_canonicalize_path():
    paths = [
        './libmisc/walk_tree.c',
        '/usr/include/cdebconf/debconfclient.h',
        '/build/anna-oYTzHL/anna-1.71/anna.c',
        '/build/mlocate-OLrxYu/mlocate-0.26/build/../src/conf.c',
        '/build/mlocate-OLrxYu/mlocate-0.26/build/gnulib/lib/../../../gnulib/lib/mbuiter.h',
        './build/gnulib/lib/../../../gnulib/lib/mbuiter.h',
        'build/gnulib/lib/../../../gnulib/lib/mbuiter.h'
    ]
    results = [
        'libmisc/walk_tree.c',
        '/usr/include/cdebconf/debconfclient.h',
        'anna.c',
        'src/conf.c',
        'gnulib/lib/mbuiter.h',
        'gnulib/lib/mbuiter.h',
        'gnulib/lib/mbuiter.h'
    ]
    for p, r in zip(paths, results):
        assert canonicalize_path(p) == r


def test_run_command():
    assert run_command(['echo', 'hello'], False)[0] == b'hello\n'
    assert run_command(['echo', 'hello'])[0] == ['hello', '']
    assert run_command(['echo', 'hello'])[1] == 0
    assert run_command(['echo111', 'hello'])[0] == ''
    assert run_command(['echo111', 'hello'])[1] == -1


def test_find_shared_libs_util():
    with open('tests/data/cmds/lddout', 'r') as f:
        stdout = f.readlines()
    res = ['/lib/x86_64-linux-gnu/libdebconfclient.so.0',
           '/lib/x86_64-linux-gnu/libdebian-installer.so.4',
           '/lib/x86_64-linux-gnu/libc.so.6', '/lib64/ld-linux-x86-64.so.2'
    ]
    assert find_shared_libs_util(stdout) == res
