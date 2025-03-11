from setuptools import Extension, setup, find_packages
from setuptools.command.sdist import sdist as SetuptoolsSdist

# This version string should be updated when releasing a new version.
_VERSION = '0.0.1'

setup(
    name = 'py-measuredns',
    version="0.1",
    packages=find_packages(),
    description = 'A python library to measure dns query latency, accurately',
    author = 'Arnav Das',
    include_package_data=True,
    ## Include data files
    package_data={
        "measure_dns": ["measuredns.c"],
    },
    requires=["wheel", "dnspython"],
    author_email = 'arnav.das88@gmail.com',
    url = 'https://docs.python.org/extending/building',
    long_description = open("README.md", "r").read(),
)