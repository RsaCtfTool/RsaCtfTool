#!/usr/bin/env python
# Use ./setup.py build_ext --inplace
from distutils.core import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize(["fact_methods.pyx", "nt_utils.pyx"])
)