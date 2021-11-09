import ipaddress
import json
import logging
import os
import shutil
import sys
import tempfile

import pyshark
import network_tools_lib

VERSION = network_tools_lib.get_version()


def run_p0f(path):
    with tempfile.TemporaryDirectory() as tempdir:
        p0f = shutil.which('p0f')
        # p0f not in PATH, default to ubuntu location.
        if p0f is None:
            p0f = '/usr/sbin/p0f'
        p0f_output = os.path.join(tempdir, 'p0f_output.txt')
        args = [p0f, '-r', path, '-o', p0f_output]
        network_tools_lib.run_proc(args)
        with open(p0f_output, 'r') as f:
            return f.read()

def parse_ip(packet):
    for ip_type in ('ip', 'ipv6'):
        try:
            ip_fields = getattr(packet, ip_type)
        except AttributeError:
            continue
        src_ip_address = getattr(ip_fields, '%s.src' % ip_type)
        dst_ip_address = getattr(ip_fields, '%s.dst' % ip_type)
        return (src_ip_address, dst_ip_address)
    return (None, None)

def parse_eth(packet):
    src_eth_address = packet.eth.src
    dst_eth_address = packet.eth.dst
    return (src_eth_address, dst_eth_address)

def run_tshark(path):
    addresses = set()
    pcap_packets = 0
    with pyshark.FileCapture(
            path, include_raw=False, keep_packets=False, debug=True,
            custom_parameters=[
                '-o', 'tcp.desegment_tcp_streams:false', '-n'],  # disable DNS
            tshark_path=os.path.join(os.path.dirname(__file__), 'tsharkwrapper.sh')) as cap:
        for packet in cap:
            pcap_packets += 1
            src_eth_address, dst_eth_address = parse_eth(packet)
            src_address, dst_address = parse_ip(packet)
            if src_eth_address and src_address:
                addresses.add((src_address, src_eth_address))
            if dst_eth_address and dst_address:
                addresses.add((dst_address, dst_eth_address))
    return (pcap_packets, addresses)

def parse_output(p0f_output, addresses):
    results = {}
    for p0f_line in p0f_output.splitlines():
        fields = p0f_line.split('|')
        fields_data = {}
        for field in fields[1:]:
            k, v = field.split('=', 1)
            fields_data[k] = v
        subj = fields_data.get('subj', None)
        host = str(ipaddress.ip_address(fields_data[subj].split('/')[0]))
        host_results = {}
        if 'os' in fields_data:
            full_os = fields_data['os']
            if not full_os.startswith('?'):
                short_os = full_os.split(' ')[0]
                host_results.update({
                    'full_os': full_os,
                    'short_os': short_os})
        for host_field in ('link', 'raw_mtu'):
            host_value = fields_data.get(host_field, None)
            if host_value is not None and not host_value.startswith('?'):
                host_results.update({host_field: host_value})
        if host_results:
            if host not in results:
                results[host] = {}
            results[host].update(host_results)
    for address, eth_address in addresses:
        if address in results:
            results[address].update({'mac': eth_address})
    return results

def ispcap(pathfile):
    for ext in ('pcap', 'pcapng', 'dump', 'capture'):
        if pathfile.endswith(''.join(('.', ext))):
            return True
    return False

def build_result_json(pcap_paths):
    all_results = []

    for path in pcap_paths:
        ipv4_addresses = {}
        ipv6_addresses = {}
        p0f_output = run_p0f(path)
        pcap_packets, addresses = run_tshark(path)
        results = parse_output(p0f_output, addresses)
        for ip, metadata in results.items():
            if metadata:
                ipv = ipaddress.ip_address(ip).version
                if ipv == 4:
                    ipv4_addresses[ip] = metadata
                else:
                    ipv6_addresses[ip] = metadata

        all_results.append({
            'tool': 'p0f',
            'version': VERSION,
            'id': os.environ.get('id', ''),
            'type': 'metadata',
            'file_path': path,
            'results': {
                'tool': 'p0f',
                'version': VERSION},
            'data': {
                'file_path': path,
                'p0f_output_size': len(p0f_output),
                'pcap_packets': pcap_packets,
                'ipv4_addresses': ipv4_addresses,
                'ipv6_addresses': ipv6_addresses},
        })
    # final record without data to indicate it's done
    all_results.append({
        'tool': 'p0f',
        'id': os.environ.get('id', ''),
        'type': 'metadata',
        'file_path': pcap_paths[0],
        'data': '',
        'results': {'tool': 'p0f', 'version': VERSION}})

    return all_results

def main():
    logging.basicConfig(level=logging.DEBUG)
    pcap_paths = []
    path = sys.argv[1]
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for pathfile in files:
                if ispcap(pathfile):
                    pcap_paths.append(os.path.join(root, pathfile))
    else:
        pcap_paths.append(path)

    result_json = build_result_json(pcap_paths)
    result_path = os.getenv('RESULT_PATH', 'result.json')
    with open(result_path, 'w') as f:
        f.write(json.dumps(result_json))


if __name__ == "__main__":  # pragma: no cover
    main()
