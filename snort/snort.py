"""
Plugin that takes pcap files and runs them through snort

Created on 6 November 2019
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
    output = ''
    alerts = ''
    try:
        output = subprocess.check_output(shlex.split("snort -c /etc/snort/etc/snort.conf -r " +
                                         path), stderr=subprocess.STDOUT)
        alerts = subprocess.check_output(shlex.split("cat /var/log/snort/alerts"))
    except Exception as e:
        print(str(e))

    print(output)
    print(alerts)
    return output, alerts

if __name__ == '__main__':  # pragma: no cover
    path = get_path()
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']

    if path:
        results, alerts = run_tool(path)
        if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
            try:
                channel = connect_rabbit()
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': results, 'results': {'tool': 'snort', 'version': get_version()}}
                send_rabbit_msg(body, channel)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': alerts, 'results': {'tool': 'snort', 'version': get_version()}}
                send_rabbit_msg(body, channel)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {'tool': 'snort', 'version': get_version()}}
                send_rabbit_msg(body, channel)
            except Exception as e:
                print(str(e))
