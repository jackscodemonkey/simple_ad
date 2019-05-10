from distutils.core import setup

setup(
    name='simple_ad',
    version='1.1',
    description='Wrapper script for python-ldap3 to perform quick lookups',
    author='Marcus Robb',
    author_email='marcus.robb@initworx.com',
    url='www.initworx.com',
    install_requires=['ldap3','pytest'],
    packages=['simple_ad'],
    scripts=['simple_ad/simple_ad.py'],
)