#!/usr/bin/env python3
"""
Setup script for XYZ Vulnerability Scanner CLI
"""

from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess
import os
import sys


# Read README for long description
def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), "r", encoding="utf-8") as fh:
        return fh.read()

def read_requirements():
    with open(os.path.join(os.path.dirname(__file__), "requirements.txt"), "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="XYZ-0-Day-Scanner",
    version="1.0.1",
    author="CyberXYZ Security Team",
    author_email="amro@cyberxyz.io",
    description="From CyberXYZ Security Inc., our research team looks for the next 0-Day vulnerabilities in collaboration with Cork Institute for Technology (CIT).",
    long_description=read_file("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/cyberxyz-security/XYZ-0-Day-Scanner",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "xyz=xyz_cli.main:main",
        ],
    },
    keywords="vulnerability scanner, security, CVE, GHSA, OSV",
    project_urls={
        "Bug Reports": "https://github.com/cyberxyz-security/XYZ-0-Day-Scanner/issues",
        "Documentation": "https://github.com/cyberxyz-security/XYZ-0-Day-Scanner",
        "Source": "https://github.com/cyberxyz-security/XYZ-0-Day-Scanner",
    },
)
