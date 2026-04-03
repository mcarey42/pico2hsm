"""Setup script for the pico2hsm Python package."""

from setuptools import setup, find_packages

with open("requirements.txt") as fh:
    install_requires = [
        line.strip()
        for line in fh
        if line.strip() and not line.startswith("#") and not line.startswith("pytest")
    ]

setup(
    name="pico2hsm",
    version="0.1.0",
    description="Host-side Python tooling for the pico2hsm HSM device",
    long_description=(
        "Python library and CLI for provisioning, managing and backing up keys "
        "on the pico2hsm — an open-source HSM based on the Raspberry Pi RP2350."
    ),
    author="pico2hsm contributors",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*"]),
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "hsm-tool=pico2hsm.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
    ],
)
