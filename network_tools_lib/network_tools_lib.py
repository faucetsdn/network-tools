import os
import subprocess


def mod_path(filename, file_for_dir=None):
    if file_for_dir is None:
        file_for_dir = __file__
    return os.path.join(os.path.dirname(os.path.realpath(file_for_dir)), filename)


def get_version():
    ver_path = os.path.join(mod_path('VERSION', __file__))
    with open(ver_path, 'r') as f:
        return f.read().strip()


def run_proc(args, output=subprocess.DEVNULL):
    with subprocess.Popen(args, stdout=output) as proc:
        proc_output = proc.communicate()
    return proc_output
