"""setup.py file."""
from setuptools import setup, find_packages
import subprocess

huawei_vrp_version = (
    subprocess.run(["git", "describe", "--tags"], stdout=subprocess.PIPE)
    .stdout.decode("utf-8")
    .strip()
)
if "-" in huawei_vrp_version:
    # when not on tag, git describe outputs: "1.3.3-22-gdf81228"
    # pip has gotten strict with version numbers
    # so change it to: "1.3.3+22.git.gdf81228"
    # See: https://peps.python.org/pep-0440/#local-version-segments
    v,i,s = huawei_vrp_version.split("-")
    huawei_vrp_version = v + "+" + i + ".git." + s

assert "-" not in huawei_vrp_version
assert "." in huawei_vrp_version

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

__author__ = 'Locus Li <locus@byto.top>'

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="napalm-huawei-vrp",
    version="v1.1.0",
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
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/napalm-huawei-vrp",
    include_package_data=True,
    install_requires=reqs,
)
