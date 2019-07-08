#! /usr/bin/env python3

"""
Convert CScout call-graph edge list to FASTEN JSON Call-Graph Format.
Dependencies: https://www.debian.org/doc/debian-policy/ch-relationships.html
"""
import os
import re
import csv
import json
import logging
import argparse
import subprocess as sp
from pydpkg import Dpkg, Dsc


class CanonicalizationError(Exception):
    pass


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
                 'constraints': '>= 9',
                 'forge': 'apt',
                 'product': 'debhelper'}

        2) input: "libdebian-installer4-dev [amd64] | libdebconfclient-dev"
           return:
                [{'architectures': 'amd64',
                  'constraints': '',
                  'forge': 'apt',
                  'product': 'libdebian-installer4-dev'},
                 {'architectures': '',
                  'constraints': '',
                  'forge': 'apt',
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
    return {'forge': forge, 'product': name, 'constraints': version,
            'architectures': arch}


def get_product_names(dependencies):
    """Get product names from a list with dependencies"""
    names = set()
    for dep in dependencies:
        if isinstance(dep, dict):
            names.add(dep['product'])
        elif isinstance(dep, list):
            for alt in dep:
                names.add(alt['product'])
    return names


def find_nth(string, sub, n):
    """Find index of nth substring in a string.

    Return:
        index of nth substring or -1.
    """
    if (n == 1):
        return string.find(sub)
    else:
        return string.find(sub, find_nth(string, sub, n - 1) + 1)


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
    return -1


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


class CScout_Canonicalizer:
    """A canonicalizer that transforms CScout Call-Graphs to FASTEN Call-Graphs

    You should always run this tool in the environment where the Call-Graph
    produced.

    **Currently it only supports Debian Packages**

    To use:
        can = CScout_Canonicalizer('directory')
        can.canonicalize()
    """
    def __init__(self, directory, forge="apt", console_logging=True,
                 file_logging=False, logging_level='DEBUG'):
        """CScout_Canonicalizer constructor.

        Args:
            directory: A directory that must contains, at least, an .deb
                or .udeb file, an .txt file with the edge list produced
                by CScout, and an .dsc file.
            forge: The forge of the analyzed package.
            console_logging: Enable logs to appear in stdout.
            file_logging: Create a file called debug.log in the 'directory'
                with the logs.
        Attributes:
            directory: directory path with CScout analysis results.
            cgraph: Call-Graph filename.
            deb: deb or udeb filename.
            dsc: dsc filename.
            forge: Product's forge.
            product: Product's name.
            source: Source's name.
            version: Product's version (string).
            dependencies: Product's dependencies (dict or list).
            can_graph: Canonicalized Call-Graph.
            orphan_deps: Dependencies that are not declared in deb or dsc.
        Raise:
            CanonicalizationError: if .txt or .deb or .dsc files not found.
        """
        self._set_logger(console_logging, file_logging, logging_level)

        self.directory = directory

        self.cgraph = find_file(self.directory, '.txt')
        if self.cgraph == -1:
            raise CanonicalizationError(".txt file not found")
        self.debs = find_files(self.directory, ('.deb', '.udeb'))
        if self.debs == -1:
            raise CanonicalizationError(".deb or .udeb file not found")
        self.dsc = find_file(self.directory, ('.dsc'))
        if self.dsc == -1:
            raise CanonicalizationError(".dsc file not found")

        self.forge = forge
        self.product = ''
        self.source = ''
        self.version = ''
        self.dependencies = ''
        self.can_graph = list()

        self.orphan_deps = set()

        # Nodes that contain one of those values are skipped from the canonical
        # Call-Graph
        self.rules = ['UNDEF', 'CScout']

    def parse_files(self):
        ds = Dsc(self.dsc)
        depends = set(safe_split(ds.headers['Build-Depends']))
        self.product = ds.headers['Binary']
        self.source = ds.headers['Source']
        self.version = ds.headers['Version']
        for deb in self.debs:
            dp = Dpkg(deb)
            depends.update(safe_split(dp.headers['Depends']))
        # Set forge as apt because they declared as Debian packages
        self.dependencies = [parse_dependency(dep, 'apt')
                             for dep in depends]

    def gen_can_cgraph(self):
        """Generate canonical Call-Graph."""
        with open(self.cgraph, 'r') as f:
            edges = csv.reader(f, delimiter=' ')
            for edge in edges:
                can_edge = self._parse_edge(edge)
                if any(r in can_edge[0] for r in self.rules) or \
                   any(r in can_edge[1] for r in self.rules):
                    continue
                self.can_graph.append(can_edge)
        self._add_orphan_dependenies()

    def save(self, filename='can_cgraph.json'):
        data = {
            'product': self.product,
            'version': self.version,
            'forge': self.forge,
            'depset': self.dependencies,
            'graph': self.can_graph
        }
        with open(filename, 'w') as f:
            json.dump(data, f)

    def canonicalize(self):
        self.parse_files()
        self.gen_can_cgraph()
        self.save(self.directory + '/can_cgraph.json')

    def _set_logger(self, console_logging, file_logging, logging_level):
        self.logger = logging.getLogger('CScout canonicalizer')
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        # create formatter
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        if console_logging:
            # create console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging_level)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        if file_logging:
            # create file handler
            fh = logging.FileHandler(self.directory + '/fcan.log')
            fh.setLevel(logging_level)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def _parse_edge(self, edge):
        node1 = self._get_uri(edge[0])
        node2 = self._get_uri(edge[1])
        return (node1, node2)

    def _get_uri(self, node):
        # TODO If we have forge we can add it to have complete URIs.
        product, namespace, function = self._parse_node(node)
        if product not in get_product_names(self.dependencies) \
                and product not in self.rules \
                and product != self.product:
            self.orphan_deps.add(product)
        return self._uri_generator(product, namespace, function)

    def _uri_generator(self, product, namespace, function):
        uri = ''
        if product != self.product:
            uri += '/' + product
        return '{}/{}/{}'.format(uri, namespace, function)

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
        elif re.match(r'^/build/[^/]*/' + self.product + '[^/]*/.*$', path):
            self.logger.debug("product match: " + path)
            return self.product
        elif path.startswith('/usr/local/include/cscout'):
            return "CScout"
        self.logger.debug("UNDEF match: " + path)
        return "UNDEF"

    def _add_orphan_dependenies(self):
        for orph in self.orphan_deps:
            # TODO find a way to detect the forge.
            self.dependencies.append({
                'architectures': '',
                'constraints': '',
                'forge': '',
                'product': orph})


def main():
    parser = argparse.ArgumentParser(description=(
        'Generate FASTEN Canonical Call Graphs'))
    parser.add_argument('directory', help=(
        'a directory with the Call Graph, and description files'))
    parser.add_argument('-f', '--forge', default='apt', help=(
        'forge of the analyzed project. For example, it could be apt, '
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
    args = parser.parse_args()
    can = CScout_Canonicalizer(args.directory,
                               forge=args.forge,
                               console_logging=args.verbose,
                               file_logging=args.file_logging,
                               logging_level=args.logging_level)
    can.canonicalize()


if __name__ == "__main__":
    main()
