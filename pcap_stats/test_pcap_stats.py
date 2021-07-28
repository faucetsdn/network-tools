"""
Test module for tcprewrite.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import sys

from .pcap_stats import condense_conversations
from .pcap_stats import get_ether_vendor
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


def test_get_ether_vendor():
    get_ether_vendor('00:00:00')


def test_condense_conversations():
    results = {'tshark': {'tcp': [{'Source': '0.0.0.0:12', 'Destination': '1.2.3.4:42'}]}}
    conv_type = 'tcp'
    prot_ip_map = condense_conversations(results, conv_type)
