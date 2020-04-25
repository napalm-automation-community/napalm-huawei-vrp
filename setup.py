"""setup.py file."""

import uuid

from setuptools import setup, find_packages

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

__author__ = 'Locus Li <locus@byto.top>'

setup(
    name="napalm-vrp",
    version="0.1.0",
    packages=find_packages(),
    author="Locus Li",
    author_email="locus@byto.top",
    description="Network Automation and Programmability Abstraction Layer with Multi-vendor support,Driver for Huawei VRP Campus Network Switch",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 3',
         'Programming Language :: Python :: 3.6',
         'Programming Language :: Python :: 3.7',
         'Operating System :: MacOS',
         'Operating System :: Linux',
    ],
    url="https://github.com/napalm-automation-community/napalm-huawei-vrp",
    include_package_data=True,
    install_requires=reqs,
)
