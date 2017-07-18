"""
Plugin that takes pcap files and splits them by server and client
ip addresses

Create on 17 July 2017
@author: Blake Pagon
"""

import os
import shlex
import subprocess
import sys

def get_path():
    path = None
    try:
        path = sys.argv[1]
    except:
        print("No path provided, quitting")
    return path

def run_tool(path):
    # need to make directories to store results from pcapsplitter
    base_dir = path.rsplit('/', 1)[0]
    try:
        os.mkdir(base_dir + '/clients')
        os.mkdir(base_dir + '/servers')
    except OSError:
        print("clients and servers directories already exist")
    try:
        subprocess.check_call(shlex.split("./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter -f " + 
                                          path + " -o " + base_dir + '/clients' + " -m client-ip"))

        subprocess.check_call(shlex.split("./PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter -f " + 
                                          path + " -o " + base_dir + '/servers' + " -m server-ip"))
    except Exception as e:
        print(str(e))

if __name__ == '__main__':
    path = get_path()
    if path:
        run_tool(path)
