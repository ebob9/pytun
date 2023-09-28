from setuptools import setup
import sys
import pytun

with open('README.md') as f:
    long_description = f.read()

if sys.version_info[:3] < (3, 6, 1):
    raise Exception("python3-pytun requires Python >= 3.6.1.")

setup(
    name="python3-pytun",
    description="Python TUN/TAP tunnel module, Python3 compatible",
    long_description=long_description,
    long_description_content_type='text/markdown',

    packages=['pytun'],
    test_suite="tests",

    version=pytun.__version__,
    author=pytun.__maintainer__,
    author_email=pytun.__email__,
    url=pytun.__url__,
    license=pytun.__license__,
    python_requires='>=3.6.1',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
