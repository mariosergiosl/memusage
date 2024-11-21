"""
Setup script for the memusage package.
"""


from setuptools import setup, find_packages


setup(
    name='memusage',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'psutil',
    ],
    entry_points={
        'console_scripts': [
            'memusage = memusage:main',
        ],
    },
)
