"""
CSV Row Parser Plugin

Breaks a CSV file down into a series of messages, one for each row.

Created on 28 October 2016
@author: Peter Bronez
"""

import csv
import sys
import json

def get_path():
    """Get the path to the input file provided by Vent"""
    path = None
    try:
        path = sys.argv[1]
    except Exception as e:
        print("no path provided: {0}, quitting.".format(str(e)))
    return path

def run_tool(path):
    """Tool entry point"""

    with open(path) as csvfile:
        print("Parsing CSV file: {0}".format(path))

        # This pure Python implimentation could be replaced with a more robust parser
        reader = csv.DictReader(csvfile)  # Assumes headers in the first row

        print("Sending CSV results: {0}".format(path))
        for row in reader:
            message = json.dumps(row)
            print("{0}".format(message))

if __name__ == '__main__':
    path = get_path()
    if path:
        run_tool(path)
