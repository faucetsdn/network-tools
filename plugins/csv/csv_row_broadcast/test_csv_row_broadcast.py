#!/usr/bin/env python
#
#   Copyright (c) 2016 In-Q-Tel, Inc, All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Test module for csv_row_broadcast.py

Created on 28 October 2016
@author: Peter Bronez
"""

import pytest
import sys

from csv_row_broadcast import get_path
from csv_row_broadcast import run_tool


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

    # TODO: spin up local RabbitMQ instance and monitor correctness
