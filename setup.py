from setuptools import setup, find_packages

setup(
    name="web-vuln-scanner",
    version="1.0.0",
    description="A BurpSuite-like Web Application Vulnerability Scanner",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "pyOpenSSL>=23.3.0",
        "cryptography>=41.0.0",
        "playwright>=1.40.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "sqlalchemy>=2.0.0",
        "pyyaml>=6.0.0",
        "jinja2>=3.1.2",
        "click>=8.1.7",
        "rich>=13.7.0",
        "numpy>=1.26.0",
        "scipy>=1.11.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "scanner=scanner.cli:main",
        ],
    },
)

