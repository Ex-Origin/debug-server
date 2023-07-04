#!/usr/bin/env python3

import os
import sys
import socket
import struct
import signal
import time
import logging

command_port    = 9545
gdb_port        = 9549
gdb_pid         = -1

COMMAND_GDB_REGISTER      = 0x01
COMMAND_GDBSERVER_ATTACH  = 0x02
COMMAND_GDB_LOGOUT        = 0x05

last_int = 0
def int_handler(signum, frame):
    global last_int
    tmp = time.time()
    if(tmp - last_int < 0.2):
        if(gdb_pid != -1):
            os.kill(gdb_pid, signal.SIGTERM)
            os.waitpid(gdb_pid, os.WNOHANG)
        exit(0)
    else:
        last_int = tmp

def term_handler(signum, frame):
    if(gdb_pid != -1):
        os.kill(gdb_pid, signal.SIGTERM)
        os.waitpid(gdb_pid, os.WNOHANG)
    exit(0)

if __name__ == '__main__':
    if(len(sys.argv) < 2):
        server_ip = os.getenv('TARGET_SERVER_IP')
        if not server_ip:
            print(f'Usage: {sys.argv[0]} [IP]', file=sys.stderr)
            exit(1)
    else:
        server_ip = sys.argv[1]

    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)
        
    command_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    if server_ip.find(':') == -1:
        logging.info(f'Connecting to {server_ip}:{command_port}')
        server_ip = '::ffff:' + server_ip
    else:
        logging.info(f'Connecting to [{server_ip}]:{command_port}')
    command_sock.sendto(struct.pack('B', COMMAND_GDB_REGISTER), (server_ip, command_port))
    data, address = command_sock.recvfrom(4096)
    logging.info(f'It has connected successfully')
    signal.signal(signal.SIGINT, int_handler)
    signal.signal(signal.SIGTERM, term_handler)
    logging.info(f'Start gdb client')
    while(True):
        data, address = command_sock.recvfrom(4096)
        option = struct.unpack('B', data[:1])[0]
        if option == COMMAND_GDBSERVER_ATTACH:
            logging.info(f'Receive COMMAND_GDBSERVER_ATTACH')
            length = struct.unpack('B', data[1:2])[0]
            gdbscript = data[2:2+length].decode()
            if(gdb_pid != -1):
                print(f"KILL the existed gdb process, pid={gdb_pid}")
                os.kill(gdb_pid, signal.SIGTERM)
                os.waitpid(gdb_pid, 0)
                gdb_pid = -1
            
            gdb_pid = os.fork()
            if(gdb_pid == 0):
                command_sock.close()
                args = ['/usr/bin/gdb-multiarch', '-q', '-ex', f'target remote {server_ip}:{gdb_port}', '-x', gdbscript]
                os.execv(args[0], args)
        elif option == COMMAND_GDB_LOGOUT:
            logging.info(f'Receive COMMAND_GDB_LOGOUT')
            if(gdb_pid != -1):
                print(f"KILL the existed gdb process, pid={gdb_pid}")
                os.kill(gdb_pid, signal.SIGTERM)
                os.waitpid(gdb_pid, 0)
                gdb_pid = -1
            break
    logging.info(f'End gdb client')
    