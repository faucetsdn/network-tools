"""
Test module for app.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import pytest
import sys

from .app import run_p0f
from .app import run_tshark
from .app import parse_output
from .app import connect
from .app import save
from .app import main

def create_test_file():
    with open('/tmp/test', 'w') as f:
        f.write("this is an invalid test file")
    with open('/tmp/p0f_output.txt', 'w') as f:
        f.write("[2017/09/13 06:19:03] mod=syn|cli=10.231.83.14/40298|srv=10.101.99.207/4506|subj=cli|os=Linux 3.11 and newer|dist=0|params=none|raw_sig=4:64+0:0:1460:mss*20,7:mss,sok,ts,nop,ws:df,id+:0\n")
        f.write("[2017/09/13 06:19:03] mod=mtu|cli=10.231.83.14/40298|srv=10.101.99.207/4506|subj=cli|link=Ethernet or modem|raw_mtu=1500\n")
        f.write("[2017/09/13 06:19:04] mod=syn+ack|cli=10.231.83.14/40298|srv=10.101.99.207/4506|subj=srv|os=???|dist=2|params=none|raw_sig=4:62+2:0:1396:mss*20,7:mss,sok,ts,nop,ws:id-:0\n")
        f.write("[2017/09/13 06:19:04] mod=mtu|cli=10.231.83.14/40298|srv=10.101.99.207/4506|subj=srv|link=???|raw_mtu=1436\n")
        f.write("[2017/09/13 06:19:04] mod=uptime|cli=10.231.83.14/40298|srv=10.101.99.207/4506|subj=cli|uptime=40 days 10 hrs 8 min (modulo 198 days)|raw_freq=257.58 Hz\n")
        f.write("[2017/09/13 06:19:04] mod=uptime|cli=10.231.83.14/40298|srv=10.101.99.207/4506|subj=srv|uptime=6 days 13 hrs 4 min (modulo 198 days)|raw_freq=238.81 Hz\n")
        f.write("[2017/09/13 06:19:04] mod=syn|cli=10.231.83.14/40300|srv=10.101.99.207/4506|subj=cli|os=Linux 3.11 and newer|dist=0|params=none|raw_sig=4:64+0:0:1460:mss*20,7:mss,sok,ts,nop,ws:df,id+:0\n")
        f.write("[2017/09/13 06:19:04] mod=mtu|cli=10.231.83.14/40300|srv=10.101.99.207/4506|subj=cli|link=Ethernet or modem|raw_mtu=1500\n")
        f.write("[2017/09/13 06:19:04] mod=uptime|cli=10.231.83.14/40300|srv=10.101.99.207/4506|subj=cli|uptime=40 days 10 hrs 8 min (modulo 198 days)|raw_freq=250.00 Hz\n")
        f.write("[2017/09/13 06:19:04] mod=syn+ack|cli=10.231.83.14/40300|srv=10.101.99.207/4506|subj=srv|os=???|dist=2|params=none|raw_sig=4:62+2:0:1396:mss*20,7:mss,sok,ts,nop,ws:id-:0\n")
        f.write("[2017/09/13 06:19:04] mod=mtu|cli=10.231.83.14/40300|srv=10.101.99.207/4506|subj=srv|link=???|raw_mtu=1436\n")
        f.write("[2017/09/13 06:19:04] mod=uptime|cli=10.231.83.14/40300|srv=10.101.99.207/4506|subj=srv|uptime=6 days 13 hrs 4 min (modulo 198 days)|raw_freq=249.52 Hz\n")
    with open('/tmp/tshark_output.txt', 'w') as f:
        f.write("	00:00:00:7f:52:89\n")
        f.write("	00:00:00:c5:1f:d4\n")
        f.write("10.231.83.14	00:00:00:c5:1f:d4\n")
        f.write("10.101.99.207	00:00:00:7f:52:89\n")
        f.write("10.101.99.68	00:00:00:7f:52:89\n")
        f.write("152.2.133.52	00:00:00:7f:52:89\n")
        f.write("204.9.54.119	00:00:00:7f:52:89\n")
        f.write("50.18.44.198	00:00:00:7f:52:89\n")
        f.write("69.89.207.99	00:00:00:7f:52:89\n")
        f.write("96.126.105.86	00:00:00:7f:52:89\n")
        f.write("	00:00:00:7f:52:89\n")
        f.write("	00:00:00:c5:1f:d4\n")
        f.write("10.231.83.14	00:00:00:c5:1f:d4\n")
        f.write("10.144.2.15	00:00:00:7f:52:89\n")
        f.write("10.101.99.207	00:00:00:7f:52:89\n")
        f.write("10.101.99.68	00:00:00:7f:52:89\n")
        f.write("152.2.133.52	00:00:00:7f:52:89\n")
        f.write("204.9.54.119	00:00:00:7f:52:89\n")
        f.write("224.0.0.251	00:00:00:00:00:fb\n")
        f.write("50.18.44.198	00:00:00:7f:52:89\n")
        f.write("69.89.207.99	00:00:00:7f:52:89\n")
        f.write("96.126.105.86	00:00:00:7f:52:89\n")
    return ['p0f', '/tmp/test']


def test_run_p0f():
    sys.argv = create_test_file()
    run_p0f()


def test_run_tshark():
    sys.argv = create_test_file()
    run_tshark()


def test_parse_output():
    sys.argv = create_test_file()
    run_p0f()
    run_tshark()
    parse_output()


def test_connect():
    r = connect()
    assert r != None


def test_save():
    r = connect()
    results = {'foo':{'bar':'baz'}}
    save(r, results)
    results = [{'foo':{'bar':'baz'}}]
    save(r, results)


def test_main():
    sys.argv = create_test_file()
    main()
