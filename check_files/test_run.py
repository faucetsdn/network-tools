"""
Test module for run.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import pytest
import sys

from .run import hash_results
from .run import av_results
from .run import main


def test_hash_results():
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    hash_results('/tmp/test')


def test_av_results():
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    av_results('/tmp/test')


def test_main():
    main('UNCONFIGURED')
