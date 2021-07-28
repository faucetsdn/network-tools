"""
Test module for pcap_to_node_pcap.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import argparse

from .pcap_to_node_pcap import get_path, ipaddress_fields, run_tool, parse_pcap_json_to_layers, pcap_name_with_layers, parse_args


def test_parse_pcap_json():
    test_pcap_json = [{
        "_source": {
            "layers": {
                "frame": {},
                "eth": {"eth.type": "0x00000800"},
                "ip": {
                    "ip.src": "192.168.254.254",
                    "ip.addr": "192.168.254.254",
                    "ip.src_host": "192.168.254.254",
                    "ip.dst": "192.168.254.4",
                    "ip.dst_host": "192.168.254.4",
                    "ip.host": "192.168.254.4",
                },
                "tcp": {
                    "tcp.srcport": "42628",
                    "tcp.dstport": "9100",
                }
            }
        }
    }]
    layers = parse_pcap_json_to_layers(test_pcap_json)
    assert layers == ['192-168-254-254', '192-168-254-4', 'frame', 'eth', 'ip', 'tcp', 'port-9100']


def test_ipaddress_fields():
    ipas = ipaddress_fields({'field': '192.168.1.1'})
    assert ipas == {'192-168-1-1'}


def test_pcap_name_with_layers():
    pcap_suffix = '.pcap'
    pcap_basename = 'trace_3cf8009a09d9684250ffa77d6f7752aee61463a8_2019-11-07_04_11_19-server-ip-74-125-68-189'
    pcap_filename = pcap_basename + pcap_suffix
    new_name = pcap_name_with_layers(pcap_filename, ['a', 'b', 'c'], pcap_suffix)
    assert new_name == pcap_basename + '-a-b-c' + pcap_suffix


def test_parse_args():
    args = parse_args(argparse.ArgumentParser(''))
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
