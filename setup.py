"""setup.py file."""
from setuptools import setup, find_packages

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

with open("README.md", "r") as fh:
    long_description = fh.read()

__author__ = "Locus Li <locus@byto.top>"

setup(
    name="napalm-huawei-vrp",
    version="v1.1.0",
    packages=find_packages(exclude=("test*",)),
    test_suite="test_base",
    author="Locus Li, Michael Alvarez",
    author_email="locus@byto.top, codingnetworks@gmail.com",
    description="Network Automation and Programmability Abstraction Layer with Multi-vendor support,Driver for VRP OS",
    license="Apache 2.0",
    long_description_content_type="text/markdown",
    long_description=long_description,
    classifiers=[
        "Topic :: Utilities",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    url="https://github.com/napalm-automation-community/napalm-huawei-vrp",
    include_package_data=True,
    install_requires=reqs,
    entry_points={
        "console_scripts": [
            "cl_napalm_configure=napalm.base.clitools.cl_napalm_configure:main",
            "cl_napalm_test=napalm.base.clitools.cl_napalm_test:main",
            "cl_napalm_validate=napalm.base.clitools.cl_napalm_validate:main",
            "napalm=napalm.base.clitools.cl_napalm:main",
        ]
    },
)
