#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from pwn import *
context.clear(arch='amd64', os='linux', log_level='debug')

attach_host = os.getenv('TARGET_SERVER_IP')
attach_port = 9545
def attach(script=''):
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    gdb_script = re.sub(r'#.*', '', 
f'''
define pr
    x/16gx $rebase(0x0)
end

b *$rebase(0x0)
''' + '\n' + script)
    gdbinit = '/tmp/gdb_script_' + attach_host
    script_f = open(gdbinit, 'w')
    script_f.write(gdb_script)
    script_f.close()
    _attach_host = attach_host
    if attach_host.find(':') == -1: _attach_host = '::ffff:' + attach_host
    tmp_sock.sendto(struct.pack('BB', 0x02, len(gdbinit.encode())) + gdbinit.encode(), (_attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
    print('attach successfully')
def strace():
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    _attach_host = attach_host
    if attach_host.find(':') == -1: _attach_host = '::ffff:' + attach_host
    tmp_sock.sendto(struct.pack('B', 0x03), (_attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
    print('strace successfully')
def address(search:str)->int:
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    _attach_host = attach_host
    if attach_host.find(':') == -1: _attach_host = '::ffff:' + attach_host
    tmp_sock.sendto(struct.pack('BB', 0x04, len(search.encode())) + search.encode(), (_attach_host, attach_port))
    tmp_recv = tmp_sock.recvfrom(4096)[0]
    tmp_sock.close()
    return struct.unpack('Q', tmp_recv[2:10])[0]
def run_service():
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # UDP
    _attach_host = attach_host
    if attach_host.find(':') == -1: _attach_host = '::ffff:' + attach_host
    tmp_sock.sendto(struct.pack('B', 0x06), (_attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
    print('run_service successfully')

sh = remote(attach_host, 9541)
attach()

sh.interactive()
