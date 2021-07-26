"""
Test module for app.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import os
import sys

from .app import VERSION
from .app import parse_output
from .app import ispcap
from .app import main
from .app import run_tshark
from .app import run_p0f
from .app import build_result_json


TEST_LO_CAP = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_lo.cap')


def test_ispcap():
    assert ispcap('afile.pcap')  # nosec
    assert not ispcap('notapcap.txt')  # nosec


def test_version():
    assert VERSION.startswith('0.')  # nosec


def test_result_json():
    assert build_result_json([TEST_LO_CAP]) == [{'data': {  # nosec
        'file_path': TEST_LO_CAP,
        'ipv4_addresses': {'127.0.0.1': {'full_os': 'Linux 2.2.x-3.x', 'mac': '00:00:00:00:00:00', 'raw_mtu': '65535', 'short_os': 'Linux'}},
        'ipv6_addresses': {'::1': {'mac': '00:00:00:00:00:00', 'raw_mtu': '65536'}}},
        'file_path': TEST_LO_CAP,
        'id': '',
        'results': {'tool': 'p0f', 'version': VERSION}, 'tool': 'p0f',
        'type': 'metadata', 'version': VERSION},
    {
        'data': '',
        'file_path': TEST_LO_CAP,
        'id': '',
        'results': {'tool': 'p0f',
        'version': VERSION},
        'tool': 'p0f',
        'type': 'metadata'}]


def test_main():
    if len(sys.argv) == 0:
        sys.argv = [os.devnull, TEST_LO_CAP]
    else:
        sys.argv[1] = TEST_LO_CAP
    main()
