#!/usr/bin/python3
# -*- coding:utf-8 -*-

import socket
import struct
import os

attach_host = '172.17.0.2'
attach_port = 9545
def attach():
    tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    gdbinit = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gdbscript.sh').encode()
    if attach_host == '': raise ValueError("Please must configure attach_host")
    tmp_sock.sendto(struct.pack('BB', 0x02, len(gdbinit)) + gdbinit, (attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
def strace():
    tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    if attach_host == '': raise ValueError("Please must configure attach_host")
    tmp_sock.sendto(struct.pack('B', 0x03), (attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
def address(search:str)->int:
    tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if attach_host == '': raise ValueError("Please must configure attach_host")
    tmp_sock.sendto(struct.pack('BB', 0x04, len(search.encode())) + search.encode(), (attach_host, attach_port))
    tmp_recv = tmp_sock.recvfrom(4096)[0]
    tmp_sock.close()
    return struct.unpack('Q', tmp_recv[2:10])[0]

if __name__ == '__main__':
    attach()