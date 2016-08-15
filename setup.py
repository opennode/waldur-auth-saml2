#!/usr/bin/env python
import sys
from setuptools import setup, find_packages


dev_requires = [
    'Sphinx==1.2.2',
]

install_requires = [
    'nodeconductor>=0.101.2',
    'djangosaml2==0.13.0',
]


setup(
    name='nodeconductor-saml2',
    version='0.2.2',
    author='OpenNode Team',
    author_email='info@opennodecloud.com',
    url='http://nodeconductor.com',
    description='NodeConductor plugin bringing SAML2-based authentication support.',
    long_description=open('README.rst').read(),
    package_dir={'': 'src'},
    packages=find_packages('src', exclude=['*.tests', '*.tests.*', 'tests.*', 'tests']),
    install_requires=install_requires,
    zip_safe=False,
    extras_require={
        'dev': dev_requires,
    },
    entry_points={
        'nodeconductor_extensions': (
            'nodeconductor_saml2 = nodeconductor_saml2.extension:SAML2Extension',
        ),
    },
    include_package_data=True,
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
    ],
)
