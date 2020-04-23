"""setup.py file."""

import uuid

from setuptools import setup, find_packages

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

__author__ = 'Locus Li <locus@byto.top>'

setup(
    name="napalm-vrp",
    version="0.1.1",
    packages=find_packages(),
    author="Locus Li",
    author_email="locus@byto.top",
    description="Network Automation and Programmability Abstraction Layer with huawei Enterprise switch(VRP) support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 3',
         'Operating System :: POSIX :: Linux',
         'Operating System :: MacOS',
    ],
    url="https://github.com/tkspuk/napalm-vrp",
    include_package_data=True,
    install_requires=reqs,
)
