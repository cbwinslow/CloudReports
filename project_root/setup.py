"""
Setup script for Enterprise Reporting System
"""

from setuptools import setup, find_packages
import os

# Read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements from requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="enterprise-reporting-system",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive enterprise reporting system for monitoring and analytics",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/enterprise-reporting",
    packages=find_packages(where="src", include=["reports", "reports.*"]),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities"
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov",
            "black",
            "flake8",
            "mypy",
            "isort",
            "pre-commit"
        ],
        "docker": [
            "docker>=5.0.0",
            "docker-compose>=1.29.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "reports=reports.cli:main",
            "reports-api=reports.api_server:main",
            "reports-web=reports.web_server:main",
            "reports-init=reports.init:main",
            "reports-diagnose=reports.diagnose:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    project_urls={
        "Homepage": "https://github.com/your-org/enterprise-reporting",
        "Documentation": "https://enterprise-reporting.readthedocs.io",
        "Repository": "https://github.com/your-org/enterprise-reporting.git",
        "Changelog": "https://github.com/your-org/enterprise-reporting/releases",
    },
)