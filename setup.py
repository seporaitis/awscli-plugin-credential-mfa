#!/usr/bin/env python
import codecs
import re

from setuptools import setup


def get_version(filename):
    with codecs.open(filename, 'r', 'utf-8') as fp:
        contents = fp.read()
    return re.search(r"__version__ = ['\"]([^'\"]+)['\"]", contents).group(1)


version = get_version('awscli_plugin_credential_mfa.py')

with codecs.open('README.rst', 'r', 'utf-8') as file_:
    readme = file_.read()

with codecs.open('HISTORY.rst', 'r', 'utf-8') as file_:
    history = file_.read()

with codecs.open('README.rst', 'r', 'utf-8') as file_:
    readme = file_.read()

with codecs.open('requirements.txt', 'r', 'utf-8') as file_:
    requirements = file_.read().splitlines()

setup(
    name='awscli-plugin-credential-mfa',
    py_modules=['awscli_plugin_credential_mfa'],
    version='0.0.1',
    description='awscli plugin enabling automatic usage of mfa token',
    long_description=readme + '\n\n' + history,
    author='Julius Seporaitis',
    author_email='julius@seporaitis.net',
    url='https://github.com/seporaitis/awscli-plugin-credential-mfa/',
    keywords=['awscli', 'plugin', 'credentials', 'mfa', 'security', 'totp', 'otp', 'aws'],
    install_requires=requirements,
    zip_safe=False,
    license='Apache 2.0',
    classifiers=[],
)
