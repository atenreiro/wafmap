# setup.py
from setuptools import setup, find_packages

setup(
    name="wafmap",
    version="1.0.0",
    description="Lightweight CLI for WAF fingerprinting and signature testing",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=[
        "click",
        "requests",
        "PyYAML",
        "prettytable",
        "scapy",
        "h2",
        "hyperframe"
    ],
    entry_points={
        "console_scripts": [
            "wafmap = wafmap.cli:cli",
        ],
    },
)