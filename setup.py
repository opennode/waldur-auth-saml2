#!/usr/bin/env python

from setuptools import setup, find_packages


install_requires = [
    'nodeconductor>=0.78.0',
    'djangosaml2==0.13.0',
]


setup(
    name='nodeconductor-saml2',
    version='0.1.2',
    author='OpenNode Team',
    author_email='info@opennodecloud.com',
    url='http://nodeconductor.com',
    description='SAML2 plugin for NodeConductor',
    package_dir={'': 'src'},
    packages=find_packages('src'),
    install_requires=install_requires,
    entry_points={
        'nodeconductor_extensions': ('nodeconductor_saml2 = nodeconductor_saml2.urls',)
    },
    zip_safe=False,
    include_package_data=True,
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ]
)
