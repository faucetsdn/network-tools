"""
Plugin that takes pcap files and rewrites them without .1Q VLAN tags

Created on 17 May 2018
@author: Charlie Lewis
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
    except:
        print("No path provided, quitting")
    return path

def run_tool(path):
    # need to make directories to store results from tcprewrite
    base_dir, file_name = path.rsplit('/', 1)
    timestamp = ""
    try:
        timestamp = '-'.join(str(datetime.datetime.now()).split(' ')) + '-UTC'
        timestamp = timestamp.replace(':', '_')
    except Exception as e:
        print("couldn't create output directory with unique timestamp")
    # make directory for tool name recognition of piping to other tools
    output_dir = os.path.join(base_dir, 'tcprewrite-dot1q' + '-' + timestamp)
    try:
        os.mkdir(output_dir)
    except OSError:
        print("couldn't make directories for output of this tool")
    try:
        subprocess.check_call(shlex.split("tcprewrite --enet-vlan=del --infile=" + path +
                                          " --outfile=" + output_dir + '/' + file_name))
    except Exception as e:
        print(str(e))

if __name__ == '__main__':
    path = get_path()
    if path:
        run_tool(path)
