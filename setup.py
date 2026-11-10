"""AgentGuard setup.py fallback.

Provides seamless compatibility for pip install -e . across both modern PEP 621
environments and legacy setuptools versions (such as setuptools 58.1 on macOS / Python 3.9).
"""

import os
import sys
import setuptools

# Version check for setuptools PEP 621 support (introduced in setuptools 61.0.0)
st_version_parts = setuptools.__version__.split(".")
try:
    major_version = int(st_version_parts[0])
except (ValueError, IndexError):
    major_version = 0

readme_path = os.path.join(os.path.dirname(__file__), "README.md") if "__file__" in locals() else "README.md"
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

if major_version < 61:
    # Setuptools < 61.0 does NOT parse [project] table from pyproject.toml.
    # Provide explicit metadata so entry_points and dependencies are registered cleanly.
    setuptools.setup(
        name="agentguard",
        version="0.1.0",
        description="OS-level zero-trust security kernel and daemon for autonomous AI agents",
        long_description=long_description,
        long_description_content_type="text/markdown",
        author="Cosmo AI Studios",
        author_email="cosmoaistudios@gmail.com",
        url="https://github.com/cosmoaistudios-netizen/AgentGuard",
        license="Apache-2.0",
        python_requires=">=3.9",
        packages=setuptools.find_packages(include=["agentguard*"]),
        install_requires=[
            "click>=8.0",
            "pydantic>=2.0",
            "pyyaml",
            "rich",
            "watchfiles",
            "numpy",
        ],
        extras_require={
            "test": ["pytest>=7.0"],
            "dev": ["pytest>=7.0"],
        },
        entry_points={
            "console_scripts": [
                "ag = agentguard.cli:main",
                "agentguard = agentguard.cli:main",
            ],
        },
        package_data={
            "agentguard": [
                "profiles/*.yaml",
                "profiles/*.yml",
                "interceptors/shim_binary/*.c",
            ],
        },
        include_package_data=True,
    )
else:
    # Modern setuptools: pyproject.toml declarative PEP 621 metadata is authoritative.
    setuptools.setup()
