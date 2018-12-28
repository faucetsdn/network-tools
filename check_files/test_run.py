"""
Test module for run.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import sys

from .run import hash_results
from .run import av_results
from .run import main

def create_test_file():
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    return '/tmp/test'

def test_hash_results():
    hash_results(create_test_file())


def test_av_results():
    av_results(create_test_file())


def test_main():
    sys.argv = ['app', create_test_file()]
    main('UNCONFIGURED')
