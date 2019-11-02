"""
Test module for tcprewrite.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import sys

from .pcap_stats import get_path
from .pcap_stats import run_capinfos
from .pcap_stats import run_tshark


def test_get_path():
    get_path()
    sys.argv = []
    get_path()


def test_run_tool():
    with open('/tmp/test', 'w') as f:
        f.write("")
    run_capinfos('/tmp/test')
    run_tshark('/tmp/test')
    with open('/tmp/test', 'w') as f:
        f.write("This is an invalid test")
    run_capinfos('/tmp/test')
    run_tshark('/tmp/test')
