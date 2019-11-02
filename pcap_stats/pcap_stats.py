"""
Plugin that takes pcap files and outputs stats

Created on 1 November 2019
@author: Charlie Lewis
"""

import datetime
import json
import os
import shlex
import subprocess
import sys

import pika


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
                          properties=pika.BasicProperties(
                          delivery_mode=2,
                         ))
    print(" [X] %s UTC %r %r" % (str(datetime.datetime.utcnow()),
                                 str(msg['id']), str(msg['file_path'])))
    return

def get_version():
    version = ''
    with open('VERSION', 'r') as f:
        for line in f:
            version = line.strip()
    return version

def get_path():
    path = None
    try:
        path = sys.argv[1]
    except Exception as e:
        print("No path provided: {0}, quitting".format(str(e)))
    return path

def run_tool(path):
    if os.path.getsize(path) == 0:
       print("pcap file empty, no stats")
       return

    output = ''
    try:
        output = subprocess.check_output(shlex.split(' '.join(['capinfos', path])))
        output = output.decode("utf-8")
        print(output)
    except Exception as e:
        print(str(e))
    return output

if __name__ == '__main__':  # pragma: no cover
    path = get_path()
    if path:
        results = run_tool(path)
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']
    if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
        try:
            channel = connect_rabbit()
            body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': results, 'results': {'tool': 'pcap_stats', 'version': get_version()}}
            send_rabbit_msg(body, channel)
            body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {'tool': 'pcap_stats', 'version': get_version()}}
            send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
