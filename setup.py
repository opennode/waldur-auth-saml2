#!/usr/bin/env python
from setuptools import setup, find_packages


dev_requires = [
    'Sphinx==1.2.2',
]

install_requires = [
    'nodeconductor>=0.146.4',
    'djangosaml2==0.16.9',
]


setup(
    name='waldur-auth-saml2',
    version='0.8.3',
    author='OpenNode Team',
    author_email='info@opennodecloud.com',
    url='http://waldur.com',
    description='Waldur plugin bringing SAML2-based authentication support.',
    long_description=open('README.rst').read(),
    license='MIT',
    package_dir={'': 'src'},
    packages=find_packages('src', exclude=['*.tests', '*.tests.*', 'tests.*', 'tests']),
    install_requires=install_requires,
    zip_safe=False,
    extras_require={
        'dev': dev_requires,
    },
    entry_points={
        'nodeconductor_extensions': (
            'waldur_auth_saml2 = waldur_auth_saml2.extension:SAML2Extension',
        ),
    },
    include_package_data=True,
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
    ],
)
