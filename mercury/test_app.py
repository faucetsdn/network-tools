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
    assert get_version() == '0.11.1.dev'


def test_parse_output():
    mercury_output = run_mercury(TEST_LO_CAP)
    result = parse_output(mercury_output)
    assert ['{"src_ip":"127.0.0.1","dst_ip":"127.0.0.1","src_port":46718,"dst_port":1025,"protocol":6,"event_start":1576897976.6209990978,"event_end":1576897976.6209990978,"fingerprints":[{"event_start":1576897976.6209990978,"tcp":"(aaaa)(0204ffd7)(04)(08)(01)(030309)"}]}', '{"src_ip":"::1","dst_ip":"::1","src_port":36728,"dst_port":1025,"protocol":6,"event_start":1576897991.0116009712,"event_end":1576897991.0116009712,"fingerprints":[{"event_start":1576897991.0116009712,"tcp":"(aaaa)(0204ffc4)(04)(08)(01)(030309)"}]}', '{"src_ip":"::1","dst_ip":"::1","src_port":36730,"dst_port":1025,"protocol":6,"event_start":1576897996.539536953,"event_end":1576897996.539536953,"fingerprints":[{"event_start":1576897996.539536953,"tcp":"(aaaa)(0204ffc4)(04)(08)(01)(030309)"}]}'] == result


def test_main():
    if len(sys.argv) == 0:
        sys.argv = [os.devnull, TEST_LO_CAP]
    else:
        sys.argv[1] = TEST_LO_CAP
    main()
