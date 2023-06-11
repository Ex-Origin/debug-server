#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from pwn import *
context.clear(arch='amd64', os='linux', log_level='debug')

attach_host = '172.17.0.2'
attach_port = 9545
def attach(script=''):
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    gdb_script = '''
define pr
    x/16gx $rebase(0x0)
end

b *$rebase(0x0)
    ''' + '\n' + script
    gdbinit = '/tmp/gdb_script_' + attach_host
    script_f = open(gdbinit, 'w')
    script_f.write(gdb_script)
    script_f.close()
    if attach_host == '': raise ValueError("Please must configure attach_host")
    tmp_sock.sendto(struct.pack('BB', 0x02, len(gdbinit.encode())) + gdbinit.encode(), (attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
    print('attach successfully')
def strace():
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    if attach_host == '': raise ValueError("Please must configure attach_host")
    tmp_sock.sendto(struct.pack('B', 0x03), (attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
    print('strace successfully')
def address(search:str)->int:
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if attach_host == '': raise ValueError("Please must configure attach_host")
    tmp_sock.sendto(struct.pack('BB', 0x04, len(search.encode())) + search.encode(), (attach_host, attach_port))
    tmp_recv = tmp_sock.recvfrom(4096)[0]
    tmp_sock.close()
    return struct.unpack('Q', tmp_recv[2:10])[0]

sh = remote('172.17.0.2', 9541)
attach()

sh.interactive()
