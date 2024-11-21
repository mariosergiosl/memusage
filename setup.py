"""
Setup script for the memusage package.
"""


from setuptools import setup, find_packages


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='memusage',
    version='0.1.0',
    author='Mario Sergio',
    author_email='mariosergiosl@gmail.com',
    description='A tool to display memory usage of processes on a Linux system',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/mariosergiosl/memusage',
    packages=find_packages(),
    install_requires=[
        'psutil',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.9',
    entry_points={
        'console_scripts': [
            'memusage = memusage:main',
        ],
    },
)
