"""
Plugin that takes pcap files and splits them by server and client
ip addresses

Created on 17 July 2017
@author: Blake Pagon
"""

import datetime
import os
import shlex
import subprocess
import sys

def get_path():
    path = None
    try:
        path = sys.argv[1]
    except Exception as e:
        print("No path provided: {0}, quitting".format(str(e)))
    return path

def run_tool(path):
    if os.path.getsize(path) < 100:
       print("pcap file too small, not splitting")
       return

    # need to make directories to store results from pcapsplitter
    base_dir = path.rsplit('/', 1)[0]
    timestamp = ""
    try:
        timestamp = '-'.join(str(datetime.datetime.now()).split(' ')) + '-UTC'
        timestamp = timestamp.replace(':', '_')
    except Exception as e:
        print("couldn't create output directory with unique timestamp")
    # make directory for tool name recognition of piping to other tools
    output_dir = os.path.join(base_dir, 'pcap-node-splitter' + '-' + timestamp)
    try:
        os.mkdir(output_dir)
        os.mkdir(output_dir + '/clients')
        os.mkdir(output_dir + '/servers')
    except OSError:
        print("couldn't make directories for output of this tool")
    try:
        subprocess.check_call(shlex.split("./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter -f " +
                                          path + " -o " + output_dir + '/clients' + " -m client-ip"))

        subprocess.check_call(shlex.split("./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter -f " +
                                          path + " -o " + output_dir + '/servers' + " -m server-ip"))
    except Exception as e:
        print(str(e))

if __name__ == '__main__':
    path = get_path()
    if path:
        run_tool(path)
