#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement

import os
from setuptools import setup, find_packages

from worldmap import NAME, VERSION, AUTHOR, CONTACT

CURRENT_DIR = os.path.dirname(__file__)

README_PATH = os.path.join(CURRENT_DIR, 'README')
if os.path.exists(README_PATH):
    with open(README_PATH) as readme:
        README = readme.read().strip()
else:
    README = ''

REQUIREMENTS_PATH = os.path.join(CURRENT_DIR, 'requirements.txt')
if os.path.exists(REQUIREMENTS_PATH):
    with open(REQUIREMENTS_PATH) as requirements:
        REQUIREMENTS = requirements.read().strip()
else:
    REQUIREMENTS = ''

setup(
    name=NAME,
    version=VERSION,
    description="Carthography",
    long_description=README,
    author=AUTHOR,
    author_email=CONTACT,
    url='http://www.free-knowledge.net',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIREMENTS,
    entry_points={
        'console_scripts': [
            'worldmap_bootstrap = worldmap.interfaces.install:main',
            'worldmap = worldmap.interfaces.gui:main'
            #'worldmap_cli = worldmap.interfaces.cli:main'
        ]
    },
    data_files=[
        ('worldmap/images/', ['worldmap/images/icone.png',
                    'worldmap/images/a_propos.png']),
        ('worldmap/core/', ['worldmap/core/modules.json',
                            'worldmap/core/knowledge.db',
                            'worldmap/core/inconsolata-dz.otf',
                            'worldmap/core/GeoLiteCity.dat'])
    ]
)

os.system('worldmap_bootstrap')
