"""
Test module for dshell_netflow_parser.py

Created on 13 June 2016
@author: Charlie Lewis, Abhi Ganesh
"""

import pytest
import sys

from .dshell_netflow_parser import get_path
from .dshell_netflow_parser import run_tool

def test_get_path():
    get_path()
    sys.argv = []
    get_path()

def test_run_tool():
    with open('test', 'w') as f:
        f.write("this is a test file")
    run_tool('test')

    with open('results.out', 'w') as f:
        f.write("2015-05-20 19:41:59.300879      0.0.0.0 ->    0.0.0.0  (US -> US)  TCP    1940   49152     0      0        0        0  0.0000s")
    run_tool('results.out')

