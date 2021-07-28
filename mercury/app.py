import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pika
import network_tools_lib

VERSION = network_tools_lib.get_version()


def connect_rabbit(host='messenger', port=5672, queue='task_queue'):
    params = pika.ConnectionParameters(host=host, port=port)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=queue, durable=True)
    return channel

def send_rabbit_msg(msg, channel, exchange='', routing_key='task_queue'):
    channel.basic_publish(exchange=exchange,
                          routing_key=routing_key,
                          body=json.dumps(msg),
                          properties=pika.BasicProperties(delivery_mode=2))
    print(" [X] %s UTC %r %r" % (str(datetime.datetime.utcnow()),
                                 str(msg['id']), str(msg['file_path'])))

def run_proc(args, output=subprocess.DEVNULL):
    proc = subprocess.Popen(args, stdout=output)
    return proc.communicate()

def run_mercury(path):
    with tempfile.TemporaryDirectory() as tempdir:
        mercury = shutil.which('pmercury')
        mercury_output = os.path.join(tempdir, 'mercury_output.txt')
        args = [mercury, '-awxg', '-r', path, '-f', mercury_output]
        run_proc(args)
        with open(mercury_output, 'r') as f:
            return f.read()

def parse_output(mercury_output):
    results = []
    for mercury_line in mercury_output.splitlines():
        results.append(json.loads(mercury_line))
    return results

def ispcap(pathfile):
    for ext in ('pcap', 'pcapng', 'dump', 'capture'):
        if pathfile.endswith(''.join(('.', ext))):
            return True
    return False

def main():
    if len(sys.argv) == 1:
        print('requires path')
        sys.exit(0)
    pcap_paths = []
    path = sys.argv[1]
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for pathfile in files:
                if ispcap(pathfile):
                    pcap_paths.append(os.path.join(root, pathfile))
    else:
        pcap_paths.append(path)

    for path in pcap_paths:
        mercury_output = run_mercury(path)
        results = parse_output(mercury_output)
        print(results)

        if os.environ.get('rabbit', '') == 'true':
            uid = os.environ.get('id', '')
            try:
                channel = connect_rabbit()
                if results:
                    body = {
                        'id': uid, 'type': 'metadata', 'file_path': path, 'data': results, 'results': {
                            'tool': 'mercury', 'version': VERSION}}
                    send_rabbit_msg(body, channel)
                if path == pcap_paths[-1]:
                    body = {
                        'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {
                            'tool': 'mercury', 'version': VERSION}}
                    send_rabbit_msg(body, channel)
            except Exception as e:
                print(str(e))


if __name__ == "__main__":  # pragma: no cover
    main()
