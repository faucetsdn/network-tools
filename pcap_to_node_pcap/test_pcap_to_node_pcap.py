"""
Test module for pcap_to_node_pcap.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import pytest
import sys

from .pcap_to_node_pcap import get_path
from .pcap_to_node_pcap import run_tool


def test_get_path():
    get_path()
    sys.argv = []
    get_path()


def test_run_tool():
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    run_tool('/tmp/test')
    with open('/tmp/test', 'w') as f:
        for x in range(100):
            f.write("This is an invalid test")
    run_tool('/tmp/test')
