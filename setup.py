"""setup.py file."""

import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements

__author__ = 'Locus Li <locus@byto.top>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-vrp",
    version="0.1.0",
    packages=find_packages(),
    author="Locus Li",
    author_email="locus@byto.top",
    description="Network Automation and Programmability Abstraction Layer with huawei Enterprise switch(VRP) support,"
                " Most of these models are S5700 series、S6700 series，etc",
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
