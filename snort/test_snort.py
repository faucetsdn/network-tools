"""
Test module for snort.py

Created on 6 November 2019
@author: Charlie Lewis
"""
import sys

from .snort import get_path
from .snort import run_tool


def test_get_path():
    get_path()


def test_run_tool():
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    run_tool('/tmp/test')
    with open('/tmp/test', 'w') as f:
        for _ in range(100):
            f.write("This is an invalid test")
    run_tool('/tmp/test')
