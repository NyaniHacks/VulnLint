from setuptools import setup, find_packages

setup(
    name="VulnLint",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'vulnlint=vulnlint.runners.cli:main',
        ],
    },

)