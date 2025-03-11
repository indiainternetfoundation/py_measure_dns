from setuptools import Extension, setup
from setuptools.command.sdist import sdist as SetuptoolsSdist

# This version string should be updated when releasing a new version.
_VERSION = '0.0.1'

setup(
    name = 'py-measuredns',
    packages=["measure_dns"],
    version = '1.0',
    description = 'A python library to measure dns query latency, accurately',
    author = 'Arnav Das',
    package_data=False,
    requires=["wheel", "dnspython"],
    author_email = 'arnav.das88@gmail.com',
    url = 'https://docs.python.org/extending/building',
    long_description = open("README.md", "r").read(),
)