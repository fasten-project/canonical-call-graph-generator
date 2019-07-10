import os
import shutil
import glob
from setuptools import setup, find_packages, Command


here = os.path.abspath(os.path.dirname(__file__))


class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    CLEAN_FILES = './build ./dist ./*.pyc ./*.tgz ./*.egg-info'.split(' ')

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        global here

        for path_spec in self.CLEAN_FILES:
            # Make paths absolute and relative to this path
            abs_paths = glob.glob(os.path.normpath(os.path.join(
                here, path_spec)))
            for path in [str(p) for p in abs_paths]:
                if not path.startswith(here):
                    # Die if path in CLEAN_FILES is absolute
                    raise ValueError("%s is not a path inside %s" % (path,
                                                                     here))
                print('removing %s' % os.path.relpath(path))
                shutil.rmtree(path)


setup(
    name='fcan',
    version='0.0.1',
    description='Canonicalize Call Graphs',
    python_requires='>=3.4, <4',
    install_requires=['pydpkg'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest', 'mock'],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'fcan=fcan.fcan:main',
        ],
    },
    cmdclass={
        'clean': CleanCommand,
    },
)