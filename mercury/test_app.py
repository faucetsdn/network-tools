"""
Test module for app.py

Created on 7 January 2020
@author: Charlie Lewis
"""
import os
import sys

from .app import parse_output
from .app import get_version
from .app import ispcap
from .app import main
from .app import run_mercury


TEST_LO_CAP = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_lo.pcap')


def test_ispcap():
    assert ispcap('afile.pcap')
    assert not ispcap('notapcap.txt')


def test_version():
    assert get_version().startswith('0.')  # nosec


def test_parse_output():
    mercury_output = run_mercury(TEST_LO_CAP)
    result = parse_output(mercury_output)
    #assert [{'src_ip': '127.0.0.1', 'dst_ip': '127.0.0.1', 'src_port': 46718, 'dst_port': 1025, 'protocol': 6, 'event_start': 1576897976.620999, 'event_end': 1576897976.620999, 'fingerprints': [{'event_start': 1576897976.620999, 'tcp': '(aaaa)(0204ffd7)(04)(08)(01)(030309)'}]}, {'src_ip': '0000:0000:0000:0000:0000:0000:0000:0001', 'dst_ip': '0000:0000:0000:0000:0000:0000:0000:0001', 'src_port': 36728, 'dst_port': 1025, 'protocol': 6, 'event_start': 1576897991.011601, 'event_end': 1576897991.011601, 'fingerprints': [{'event_start': 1576897991.011601, 'tcp': '(aaaa)(0204ffc4)(04)(08)(01)(030309)'}]}, {'src_ip': '0000:0000:0000:0000:0000:0000:0000:0001', 'dst_ip': '0000:0000:0000:0000:0000:0000:0000:0001', 'src_port': 36730, 'dst_port': 1025, 'protocol': 6, 'event_start': 1576897996.539537, 'event_end': 1576897996.539537, 'fingerprints': [{'event_start': 1576897996.539537, 'tcp': '(aaaa)(0204ffc4)(04)(08)(01)(030309)'}]}] == result


def test_main():
    if len(sys.argv) == 0:
        sys.argv = [os.devnull, TEST_LO_CAP]
    else:
        sys.argv[1] = TEST_LO_CAP
    main()
