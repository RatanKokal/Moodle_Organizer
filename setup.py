from setuptools import setup, find_packages

setup(
    name='moodle-cli',
    version='2.0.0',
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'pyyaml',
        'tqdm',
        'pycryptodome',
    ],
    entry_points={
        'console_scripts': [
            'moodle=moodle_cli.main:main',
        ],
    },
)