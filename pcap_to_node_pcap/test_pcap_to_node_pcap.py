"""
Test module for pcap_to_node_pcap.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import argparse
import sys

from .pcap_to_node_pcap import get_path, run_tool, pcap_name_with_layers, parse_args


def test_pcap_name_with_layers():
    pcap_suffix = '.pcap'
    pcap_basename = 'trace_3cf8009a09d9684250ffa77d6f7752aee61463a8_2019-11-07_04_11_19-server-ip-74-125-68-189'
    pcap_filename = pcap_basename + pcap_suffix
    new_name = pcap_name_with_layers(pcap_filename, ['a', 'b', 'c'], pcap_suffix)
    assert new_name == pcap_basename + '-a-b-c' + pcap_suffix

def test_parse_args():
    args = parse_args(argparse.ArgumentParser([]))
    assert args.protoannotate


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
