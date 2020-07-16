"""
Test module for app.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import os
import sys

from .app import parse_output
from .app import get_version
from .app import ispcap
from .app import main
from .app import run_tshark
from .app import run_p0f


TEST_LO_CAP = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_lo.cap')


def test_ispcap():
    assert ispcap('afile.pcap')
    assert not ispcap('notapcap.txt')


def test_version():
    assert get_version() == '0.11.13.dev'


def test_parse_output():
    p0f_output = run_p0f(TEST_LO_CAP)
    src_addresses = run_tshark(TEST_LO_CAP)
    result = parse_output(p0f_output, src_addresses)
    assert {
        '127.0.0.1': {
            'full_os': 'Linux 2.2.x-3.x', 'short_os': 'Linux', 'raw_mtu': '65535', 'mac': '00:00:00:00:00:00'},
        '::1': {
            'raw_mtu': '65536', 'mac': '00:00:00:00:00:00'}} == result


def test_main():
    if len(sys.argv) == 0:
        sys.argv = [os.devnull, TEST_LO_CAP]
    else:
        sys.argv[1] = TEST_LO_CAP
    main()
