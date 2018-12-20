"""
DShell netflow parser plugin

Created on 13 June 2016
@author: Charlie Lewis, Abhi Ganesh
"""

import subprocess
import sys

def get_path():
    path = None
    try:
        path = sys.argv[1]
    except Exception as e:
        print("no path provided: {0}, quitting.".format(str(e)))
    return path

def run_tool(path):
    """Tool entry point"""
    subprocess.Popen('/Dshell/dshell-decode -o results.out -d netflow '+path,
                     shell=True, stdout=subprocess.PIPE).wait()
    try:
        with open('results.out', 'r') as f:
            for rec in f:
                data = {}
                rec = rec.strip()
                fields = rec.split()
                try:
                    data["date"] = fields[0].strip()
                    data["time"] = fields[1].strip()
                    data["src_ip"] = fields[2].strip()
                    data["dst_ip"] = fields[4].strip()
                    data["src_country_code"] = fields[5].strip()[1:]
                    data["dst_country_code"] = fields[7].strip()[:-1]
                    data["protocol"] = fields[8].strip()
                    data["src_port"] = fields[9].strip()
                    data["dst_port"] = fields[10].strip()
                    data["src_packets"] = fields[11].strip()
                    data["dst_packets"] = fields[12].strip()
                    data["src_bytes"] = fields[13].strip()
                    data["dst_bytes"] = fields[14].strip()
                    data["duration"] = fields[15].strip()
                    data["tool"] = "dshell_netflow"
                    print(str(data))
                except Exception as e:
                    print('failed to create dict because: {0}'.format(str(e)))
    except Exception as e:
        print('failed process results because: {0}'.format(str(e)))

if __name__ == '__main__':
    path = get_path()
    if path:
        run_tool(path)
