"""
GhostNet setup.py
Install with: pip install -e .
Then run: ghostnet dashboard
"""

from setuptools import setup, find_packages

setup(
    name="ghostnet",
    version="2.4.1",
    description="AI-Powered Network Intelligence System · Powered by Claude",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GhostNet Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "anthropic>=0.30.0",
        "rich>=13.7.0",
        "flask>=3.0.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "scanner": [
            "scapy>=2.5.0",
            "python-nmap>=0.7.1",
        ],
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
            "black",
            "ruff",
        ],
    },
    entry_points={
        "console_scripts": [
            "ghostnet=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    keywords="network security wifi intelligence claude ai terminal",
)
