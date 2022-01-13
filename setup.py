"""setup.py file."""
from setuptools import setup, find_packages

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

__author__ = 'Locus Li <locus@byto.top>'

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="napalm-huawei-vrp",
    version="1.0.0",
    packages=find_packages(),
    author="Locus Li",
    author_email="locus@byto.top",
    description="Network Automation and Programmability Abstraction Layer with Multi-vendor support,Driver for Huawei Campus Network Switch,VRP OS",
    long_description_content_type="text/markdown",
    long_description=long_description,

    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/napalm-huawei-vrp",
    include_package_data=True,
    install_requires=reqs,
)
