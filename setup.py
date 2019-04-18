from setuptools import setup, find_packages
from pathlib import Path

README_PATH = Path(__file__).parent / 'README.md'
with README_PATH.open() as readme_file:
    README = readme_file.read()

setup(
    name='blockchain',
    version='0.0.1',
    packages=find_packages(),#['blockchain'],
    include_package_data=True,
    description='A blockchain implementation in python',
    long_description=README,
    license='MIT License',
    author='Gergely Tabiczky',
    author_email='tgergo@runbox.com',
    classifiers=[
        'blockchain',
        'cryptocurrency'
    ]
)
