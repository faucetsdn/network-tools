"""
Test module for csv_row_broadcast.py

Created on 28 October 2016
@author: Peter Bronez
"""

import pytest
import sys

from .csv_row_broadcast import get_path
from .csv_row_broadcast import run_tool


def test_get_path():
    get_path()
    sys.argv = []
    get_path()


def test_run_tool():
    with open('/tmp/test', 'w') as f:
        f.write("Column 1,col2,col_3\n")
        f.write("Row 1,foo,bar\n")
        f.write("row 2,baz,42\n")
    run_tool('/tmp/test')
