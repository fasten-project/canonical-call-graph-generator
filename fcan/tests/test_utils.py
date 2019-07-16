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
from fcan.fcan import safe_split, extract_text, parse_dependency, find_nth,\
        get_product_names, find_file, find_files, check_custom_deps


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


simple_product = {'architectures': "", 'constraints': ">= 9",
                  'forge': "debian", 'product': "debhelper"}
complex_product = [{'architectures': "amd64", 'constraints': "",
                    'forge': "debian", 'product': "libdebian-installer4-dev"},
                   {'architectures': "", 'constraints': "", 'forge': "debian",
                    'product': "libdebconfclient-dev"}]


def test_parse_dependency():
    assert parse_dependency("debhelper (>= 9)", "debian") == simple_product
    assert parse_dependency(
        "libdebian-installer4-dev [amd64] | libdebconfclient-dev",
        "debian") == complex_product


def test_get_product_names():
    assert get_product_names([simple_product]) == set(['debhelper'])
    assert get_product_names([complex_product]) == \
        set(['libdebian-installer4-dev', 'libdebconfclient-dev'])
    assert get_product_names([simple_product, complex_product]) == \
        set(['debhelper', 'libdebian-installer4-dev', 'libdebconfclient-dev'])


def test_find_nth():
    assert find_nth('foo foo bar foo', 'foo', 1) == 0,\
        "Should return 0"
    assert find_nth('foo foo bar foo', 'foo', 2) == 4,\
        "Should return 4"
    assert find_nth('foo foo bar foo', 'foo', 3) == 12,\
        "Should return 12"
    assert find_nth('foo foo bar foo', 'foo', 4) == -1,\
        "Should return -1"
    assert find_nth('foo foo bar foo', 'bar', 1) == 8,\
        "Should return 8"
    assert find_nth('foo foo bar foo', 'bar', 2) == -1,\
        "Should return -1"
    assert find_nth('foo foo bar foo', 'bur', 2) == -1,\
        "Should return -1"


def test_find_file():
    dirs_path = '{}/{}/{}/'.format(os.path.curdir, 'tests', 'data')
    assert find_file(dirs_path + 'package1', ('.txt')) is None,\
        "Should return -1"
    res1 = find_file(dirs_path + 'package2', ('.txt')).endswith('.txt')
    res2 = find_file(dirs_path + 'package2', ('.dsc')).endswith('.dsc')
    assert res1 is True, "Should be True"
    assert res2 is True, "Should be True"


def test_find_files():
    dirs_path = '{}/{}/{}/'.format(os.path.curdir, 'tests', 'data')
    assert len(find_files(dirs_path + 'package1', ('.deb', '.udeb'))) == 0,\
        "Should return an empty list"
    assert len(find_files(dirs_path + 'package2', ('.deb', '.udeb'))) == 1,\
        "Should return a list with one file"
    assert len(find_files(dirs_path + 'package3', ('.deb', '.udeb'))) == 3,\
        "Should return a list with 3 files"


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
