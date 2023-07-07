#!/usr/bin/env python3

import os
import shutil

if __name__ == '__main__':

    if(os.access('./exp.py', os.F_OK) == 0):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(os.readlink(__file__))), 'exp.py'), './exp.py')
        os.chmod('./exp.py', 0o755)

    if(os.access('./debug-server', os.F_OK) == 0):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(os.readlink(__file__))), 'release/debug-server.x86_64'), './debug-server')
        os.chmod('./debug-server', 0o755)
