"""
Test module for app.py

Created on 20 December 2018
@author: Charlie Lewis
"""
import os
import sys
import tempfile

from .app import run_p0f
from .app import run_tshark
from .app import parse_output
from .app import connect
from .app import get_version
from .app import ispcap
from .app import save
from .app import main


def create_test_output(p0f_output, tshark_output):
    with open(p0f_output, 'w') as f:
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
    with open(tshark_output, 'w') as f:
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


def test_ispcap():
    assert ispcap('afile.pcap')
    assert not ispcap('notapcap.txt')


def test_version():
    assert get_version() == '0.1.7'


def test_run_p0f():
    print(run_p0f(os.devnull, os.devnull))


def test_run_tshark():
    print(run_tshark(os.devnull, os.devnull))


def test_parse_output():
    with tempfile.TemporaryDirectory() as tempdir:
        p0f_output = os.path.join(tempdir, 'p0f_output.txt')
        tshark_output = os.path.join(tempdir, 'tshark_output.txt')
        create_test_output(p0f_output, tshark_output)
        result = parse_output(p0f_output, tshark_output)
        assert result == {'10.231.83.14': {'full_os': 'Linux 3.11 and newer', 'short_os': 'Linux', 'mac': '00:00:00:c5:1f:d4'}}


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
    with tempfile.TemporaryDirectory() as tempdir:
        if len(sys.argv) == 0:
            sys.argv = [os.devnull, tempdir]
        else:
            sys.argv[1] = tempdir
        main()
