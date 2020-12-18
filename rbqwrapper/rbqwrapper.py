#!/usr/bin/env python

"""
Run a provided tool with arguments, look for a correctly formatted JSON result, and send it over RabbitMQ.

Usage:

    rbqwrapper.py /tool/executable arg arg...

The tool must output a JSON file of the following form (using mac_addresses, ipv4_addresses, or ipv6_addresses):

{
   "tool": "tool name",
   "data": {
       "mac_addresses": {
           "01:02:03:04:05:06": { ..metadata for MAC.. },
       },
   },
}
"""

import logging
import json
import os
import socket
import subprocess
import sys

import pika


class RbqWrapper:

    def __init__(self):
        logging.basicConfig(
            level=logging.DEBUG,
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger('rbqwrapper')
        self.result_path = os.getenv('RESULT_PATH', 'result.json')
        self.rabbit_host = os.getenv('RABBIT_HOST', 'messenger')
        self.rabbit_queue_name = os.getenv('RABBIT_QUEUE_NAME', 'task_queue')
        self.rabbit_exchange = os.getenv('RABBIT_EXCHANGE', 'task_queue')
        self.rabbit_port = int(os.getenv('RABBIT_PORT', '5672'))
        self.rabbit_routing_key = os.getenv('RABBIT_ROUTING_KEY', 'task_queue')

    def _connect_rabbit(self):
        params = pika.ConnectionParameters(host=self.rabbit_host, port=self.rabbit_port)
        connection = pika.BlockingConnection(params)
        channel = connection.channel()
        channel.queue_declare(queue=self.rabbit_queue_name, durable=True)
        self.logger.info('_connect_rabbit: channel open %s:%u', self.rabbit_host, self.rabbit_port)
        return (connection, channel)

    def _send_rabbit_msg(self, msg, channel):
        body = json.dumps(msg)
        channel.basic_publish(
            exchange=self.rabbit_exchange,
            routing_key=self.rabbit_routing_key,
            body=body,
            properties=pika.BasicProperties(delivery_mode=2))
        self.logger.info('_send_rabbit_msg: %s', body)

    def _validate_results(self, results):
        for required_field in ('tool', 'data'):
            if required_field not in results:
                self.logger.error('results are missing field %s', required_field)
                return False
        data = results.get('data', None)
        if not isinstance(data, dict):
            self.logger.error('results data must be a dict')
            return False
        for required_metadata_field in ('mac_addresses', 'ipv4_addresses', 'ipv6_addresses'):
            required_metadata = data.get(required_metadata_field, None)
            if isinstance(required_metadata, dict):
                return True
        self.logger.error('required metadata field not present')
        return False

    def output_msg(self):
        try:
            with open(self.result_path) as result_path:
                results = json.load(result_path)
        except (FileNotFoundError,) as err:
            self.logger.info('could not read/parse JSON results from %s: %s', self.result_path, err)
            return
        self.logger.info('read %s', results)
        if not self._validate_results(results):
            return
        try:
            (connection, channel) = self._connect_rabbit()
            self._send_rabbit_msg(results, channel)
            connection.close()
        except (socket.gaierror, pika.exceptions.AMQPConnectionError) as err:
            self.logger.error('Failed to send Rabbit message %s because: %s', results, err)


def main(argv):
    if argv:
        try:
            subprocess.check_call(argv)
        except subprocess.CalledProcessError as err:
            sys.exit(err.returncode)
        rbqwrapper = RbqWrapper()
        if self.rabbit_host:
            rbqwrapper.output_msg()


if __name__ == '__main__':  # pragma: no cover
    main(sys.argv[1:])
