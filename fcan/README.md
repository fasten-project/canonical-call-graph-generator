# fcan

Canonicalize C Call Graphs to FASTEN JSON format described in deliverable
2.1.

__Currently it only supports call graphs of Debian Packages.__


Input
-----
fcan needs as input a directory that must contain:

* a **.txt** file with an edge list. The nodes should be separated with spaces;
each node should contain the type of the function (static/public),
the absolute path of the file that contains the function, and
the name of the function. Colons should separate all of them.


```
public:/build/anna-xjzj1e/anna-1.58/anna.c:main public:/usr/include/stdlib.h:getenv
public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever static:/usr/include/cdebconf/debconfclient.h:debconf_set
...
```

* a Debian source control file ([.dsc](https://wiki.debian.org/dsc)).
* at least a [.deb](https://wiki.debian.org/deb) or a
[.udeb](https://wiki.debian.org/udeb) file.

You can find an example directory [here](https://github.com/fasten-project/canonical-call-graph-generator/tree/master/fcan/tests/data/anna-1.58).

Requirements
------------
To run fcan you should have installed python3 pip3 and the dpkg suite
(package manager for Debian). You should always run fcan
in the same environment that you run your analysis (online analysis).

Internals
---------

* **Find dependencies:** To find dependencies we parse the .dep and .udeb files
with the pydpkg library. We can also get the dependencies from the
user-specified custom deps file.
* **Find the product for each node:** We use the ```dpkg``` tool with
the switch ```-S``` and the path of each node to detect in which product
each function belongs. If that failed, we use regular expressions to
match paths with products. Finally, if none regex matches a path,
then the product for this node is set to UNDEFINED.
Finally, we don't include edges that have nodes
with UNDEFINED products in canonical call graphs.

Output
------
The FASTEN JSON format is described in deliverable 2.1.
It is a JSON with the following keys:

* __forge__: The name of the forge associated with this revision.
* __product__: The name of the product associated with this revision.
* __version__: The version associated with this revision.
* __depset__: An array of JSON objects representing a dependency set.
Each object has a key forge, a key product, a key constraints, and a
key architecture. All those details come from the .deb files or user
input.
* __graph__: A list of pairs of FASTEN schemeless URIs that composed from
the product, the namespace, and the function name.
The namespace is 'C' for public functions
or the encoded absolute path of the file for static functions.

Options
-------
fcan provides a command-line interface with many abilities.
The positional parameter must be the directory in which included the files
that described in **Input**.

```
usage: fcan [-h] [-f FORGE] [-v] [-L] [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]
            [-c CUSTOM_DEPS] [-r REGEX_PRODUCT] [-o OUTPUT]
            directory

Canonicalize Call Graphs to FASTEN Canonical Call Graphs

positional arguments:
  directory             a directory with the Call Graph, and description files

optional arguments:
  -h, --help            show this help message and exit
  -f FORGE, --forge FORGE
                        forge of the analyzed project. For example, it could
                        be debian, or GitHub
  -v, --verbose         print logs to the console
  -L, --file-logging    save logs to a file
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --logging-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        logging level for logs
  -c CUSTOM_DEPS, --custom-deps CUSTOM_DEPS
                        custom user defined dependencies
  -r REGEX_PRODUCT, --regex-product REGEX_PRODUCT
                        regex to match product's files
  -o OUTPUT, --output OUTPUT
                        file to save the canonicalized call graph
```

* **custom-deps:** A JSON file that consists of JSON objects whereas the
keys are product names and have a key forge, a key version, a key constraints,
a key architecture, a key regex which has a list with regexes to match paths,
a key keep that has a boolean value to keep or not nodes in the canonicalized
call graph.

Example
-------

* Input call graph

```
public:/build/anna-xjzj1e/anna-1.58/anna.c:main public:/usr/include/stdlib.h:getenv
public:/build/anna-xjzj1e/anna-1.58/retriever.c:set_retriever static:/usr/include/cdebconf/debconfclient.h:debconf_set
static:/usr/local/include/cscout/csmake-pre-defs.h:__attribute__ static:/usr/include/x86_64-linux-gnu/bits/sigset.h:__sigmask
public:/build/anna-xjzj1e/anna-1.58/anna.c:main public:/usr/include/debian-installer/system/packages.h:di_system_package_check_subarchitecture
public:/build/anna-xjzj1e/anna-1.58/anna.c:main static:/usr/include/debian-installer/system/packages.h:di_system_packages_status_read_file
public:/build/anna-xjzj1e/anna-1.58/anna.c:main public:/usr/local/include/my_dep/utils.h:sum
```

* [dsc](https://github.com/fasten-project/canonical-call-graph-generator/blob/master/fcan/tests/data/anna-1.58/anna_1.58.dsc)
and [udeb](https://github.com/fasten-project/canonical-call-graph-generator/blob/master/fcan/tests/data/anna-1.58/anna_1.58_amd64.udeb) files

* Custom Deps

```
{
    "my_dep": {
        "forge": "github",
        "constraints": "",
        "architecture": "",
        "regex": [
            "^/usr/local/include/my_dep/.*"
        ],
        "keep": true
    },
    "CScout": {
        "forge": "",
        "constraints": "",
        "architecture": "",
        "regex": [
            "^/usr/local/include/cscout.*"
        ],
        "keep": false,
    }
}
```

* Canonical Call Graph

```
{
    "product": "anna",
    "version": "1.58",
    "forge": "debian",
    "depset": [
        {
            "forge": "debian",
            "product": "libdebian-installer4-dev",
            "constraints": ">= 0.109",
            "architectures": ""
        },
        {
            "forge": "debian",
            "product": "debhelper",
            "constraints": ">= 9",
            "architectures": ""
        },
        {
            "forge": "debian",
            "product": "dpkg-dev",
            "constraints": ">= 1.15.7",
            "architectures": ""
        },
        {
            "forge": "debian",
            "product": "libdebconfclient0-dev",
            "constraints": ">= 0.46",
            "architectures": ""
        },
        {
            "forge": "github",
            "product": "my_dep",
            "constraints": "",
            "architecture": ""
        },
        {
            "forge": "UNDEFINED",
            "product": "libc6-dev",
            "architectures": "",
            "constraints": ""
        }
    ],
    "graph": [
        [
            "/C/main()",
            "//libc6-dev/C/getenv()"
        ],
        [
            "/C/set_retriever()",
            "//libdebconfclient0-dev/%2Fusr%2Finclude%2Fcdebconf/debconfclient.h;debconf_set()"
        ],
        [
            "/C/main()",
            "//libdebian-installer4-dev/C/di_system_package_check_subarchitecture()"
        ],
        [
            "/C/main()",
            "//libdebian-installer4-dev/%2Fusr%2Finclude%2Fdebian-installer%2Fsystem/packages.h;di_system_packages_status_read_file()"
        ],
        [
            "/C/main()",
            "//my_dep/C/sum()"
        ]
    ]
}

```

Install fcan
------------

Make sure you have installed ```dpkg```.

```
python setup.py install
```

Run CScout analysis and fcan with Docker
----------------------------------------
Make sure you have installed docker and docker-compose, then run the
following commands.

```
# Clone Repository with Dockerfiles to run CScout to produce Call Graphs
git clone https://github.com/fasten-project/debian-builder
cd debian-builder
# Deactivate buildd and cron daemons
sed -i '2,3 {s/^/#/}' cscout/init_scripts/daemon.sh
# Build and run the docker images
./run_analysis.sh cscout
# Login to the image
docker exec -it cscout_cscout_1 bash
# Change user to buildd
su buildd
# Run CScout analysis and produce FASTEN call graph
sbuild --apt-update --no-apt-upgrade --no-apt-distupgrade --batch --stats-dir=/var/lib/buildd/stats --dist=stretch --sbuild-mode=buildd --arch=amd64 package-name
# The callgraph will be created in cscout/callgraphs/package-name-version/can_graph.json
# Stop and remove the container
cd cscout && docker-compose down -v
```

Run tests
---------

```
python setup.py test
```
