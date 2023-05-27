#!/usr/bin/python3

import os
import shutil

if __name__ == '__main__':

    if(os.access('./exp.py', os.F_OK) == 0):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(os.readlink(__file__))), 'exp.py'), './exp.py')
        os.chmod('./exp.py', 0o755)

    if(os.access('./gdbscript.sh', os.F_OK) == 0):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(os.readlink(__file__))), 'gdbscript.sh'), './gdbscript.sh')
        os.chmod('./gdbscript.sh', 0o644)
        
    if(os.access('./debug-server.c', os.F_OK) == 0):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(os.readlink(__file__))), 'debug-server.c'), './debug-server.c')
        os.chmod('./debug-server.c', 0o644)

    if(os.access('./attach.py', os.F_OK) == 0):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(os.readlink(__file__))), 'debug-server.c'), './debug-server.c')
        os.chmod('./attach.py', 0o755)
