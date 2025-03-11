import os
import sys
from distutils.core import setup, Extension

from distutils.command.build_ext import build_ext
import subprocess
import re

# This version string should be updated when releasing a new version.
_VERSION = '0.0.1'

setup(
    name = 'py-measuredns',
    version = '1.0',
    description = 'A python library to measure dns query latency, accurately',
    author = 'Arnav Das',
    author_email = 'arnav.das88@gmail.com',
    url = 'https://docs.python.org/extending/building',
    long_description = open("README.md", "r").read(),
)