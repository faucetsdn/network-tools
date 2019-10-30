"""
Test module for pcap_to_node_pcap.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import sys

from .pcap_to_node_pcap import get_path
from .pcap_to_node_pcap import run_tool


def test_get_path():
    get_path([])
    get_path(['xxx'])


def test_run_tool():
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    for annotate in (True, False):
        run_tool('/tmp/test', annotate)
    with open('/tmp/test', 'w') as f:
        for _ in range(100):
            f.write("This is an invalid test")
    for annotate in (True, False):
        run_tool('/tmp/test', annotate)
