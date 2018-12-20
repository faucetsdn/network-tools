"""
Test module for app.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import pytest
import sys

from .app import run_p0f
from .app import run_tshark
from .app import parse_output
from .app import connect
from .app import save
from .app import main


def test_run_p0f():
    with open('/tmp/test', 'w') as f:
        f.write("this is an invalid test file")
    sys.argv = ['p0f', '/tmp/test']
    run_p0f()


def test_run_tshark():
    with open('/tmp/test', 'w') as f:
        f.write("this is an invalid test file")
    sys.argv = ['p0f', '/tmp/test']
    run_tshark()


def test_parse_output():
    with open('/tmp/test', 'w') as f:
        f.write("this is an invalid test file")
    sys.argv = ['p0f', '/tmp/test']
    run_p0f()
    run_tshark()
    parse_output()


def test_connect():
    r = connect()
    assert r != None


def test_save():
    r = connect()
    results = {'foo':{'bar':'baz'}}
    save(r, results)
    results = [{'foo':{'bar':'baz'}}]
    save(r, results)


def test_main():
    with open('/tmp/test', 'w') as f:
        f.write("this is an invalid test file")
    sys.argv = ['p0f', '/tmp/test']
    main()
