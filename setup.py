# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='RsaCtfTool',
    version='1.0.0',
    description='RSA attack tool (mainly for ctf) - retreive private key from weak public key and/or uncipher data',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Ganapati/RsaCtfTool',
    author='ganapati (@G4N4P4T1)',
    packages=find_packages(exclude=["scripts.*", "scripts"]),
    include_package_data=True,
    install_requires=open('requirements.txt').read().splitlines(),
    entry_points={
        'console_scripts': [
            'RsaCtfTool = RsaCtfTool.RsaCtfTool:cli'
        ]
    },
    classifiers=[
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
    project_urls={
        'Bug Reports': 'https://github.com/Ganapati/RsaCtfTool/issues',
        'Source': 'https://github.com/Ganapati/RsaCtfTool',
    },
)