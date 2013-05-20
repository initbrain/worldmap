# -*- coding: utf-8 -*-

import os
import inspect
import worldmap

WORLDMAP_PATH = os.path.dirname(inspect.getfile(worldmap))
CONFIG_PATH = os.path.join(WORLDMAP_PATH, 'config')