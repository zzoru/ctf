from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from socket import *
from pwn import *
import re

def recv_num(n):
    r = ''
    for _ in range(n):
        c = s.recv(1)
        if not c:
            break

        r += c
        if len(r) == n:
            break

    return r

s = None
SYS_READ = 0
SYS_WRITE = 1
answer = [0 for i in range(8)]
answer2 = [0 for i in range(8)]

count = 0
count2 = 0

def hook_code(uc, address, size, user_data):
    global count2
    eip = uc.reg_read(UC_X86_REG_RIP)
    r11 = uc.reg_read(UC_X86_REG_R11)
    if uc.mem_read(eip, size)[0] == 0x41:
        eax = uc.reg_read(UC_X86_REG_RAX)        
        uc.mem_write(0x5000000 + count2 , chr(eax))
        answer2[count2] = chr(eax)   
        count2 = count2 + 1

def hookingSyscall(mu, data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    rdi = mu.reg_read(UC_X86_REG_RDI)
    rsi = mu.reg_read(UC_X86_REG_RSI)
    rdx = mu.reg_read(UC_X86_REG_RDX)

    if rax == SYS_READ:
        data = ''
        if count <= 30:
            data = ''.join(answer)    
            
        elif count <=60:
            global count2            
            count2 = 0
            print(answer)
            print(answer2)
            data = ''.join(answer) + ''.join(answer2)
            print(data)
        else:
            data = 'test'
        mu.mem_write(rsi, data[:rdx])
        s.send(data)

    elif rax == SYS_WRITE:
        a = mu.mem_read(rsi, rdx)
        print(a)



    else:
        print('[-] We don\'t support other SYSCALL')
        exit(0)

def play():
    ADDRESS = 0x1000000
    STACK = 0x3000000
    BUFFER = 0x5000000
    START_ADDRESS = ADDRESS + 1 * 1024 * 1024
    
    """
    MOV [RSP + 0x20], 0x5000000
    MOV RAX, 0x1000000
    CALL RAX
    MOV RAX, 0x1001000
    CALL RAX
    """

    START_CODE = '48c744242000000005'.decode('hex')
    START_CODE += '48c7c000000001ffd0'.decode('hex')
    START_CODE += '48c7c000100001ffd0'.decode('hex')
    X86_CODE64 = recv_num(0x2000)
    if not X86_CODE64:
        return False

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    mu.mem_map(STACK, 2 * 1024 * 1024)
    mu.mem_map(BUFFER, 2 * 1024 * 1024)
    if count <= 30:
        regrex = re.compile('\xb0.{1}\x3a\x46.{1}')
        regrex2 = re.compile('\xb0.{1}\x3a\x06')
        a = regrex.findall(X86_CODE64)
        b = regrex2.findall(X86_CODE64)
        if len(a) > 0:
            for i in a:         
                answer[ord(i[4])] = i[1]
            for j in b:
                answer[0] = j[1]
            print(answer)
    elif count <=50: 
        answer1 = p64(u64(X86_CODE64[0x106a:0x106a+8]) ^ 0x9090909090909090)
        code_len = ord(X86_CODE64[0x1064])
        xored_code = X86_CODE64[0x106a:0x106a + code_len]
        for i in range(0, len(answer1)):
            answer[i] = answer1[i]
        print(code_len)
        real_code = ''
        for i in range(0, code_len, 8):
            real_code += p64(u64(xored_code[i: i+8].ljust(8,'\x00')) ^ u64(answer1))

        ADDRESS = 0x1000000
        STACK = 0x3000000
        BUFFER = 0x5000000
        START_ADDRESS = ADDRESS + 1 * 1024 * 1024
        mu2 = Uc(UC_ARCH_X86, UC_MODE_64)
        mu2.mem_map(ADDRESS, 2 * 1024 * 1024)
        mu2.mem_map(STACK, 2 * 1024 * 1024)
        mu2.mem_map(BUFFER, 2 * 1024 * 1024)
        mu2.reg_write(UC_X86_REG_RSP, STACK + 1 * 1024 * 1024)
        mu2.reg_write(UC_X86_REG_R11, BUFFER)
        mu2.mem_write(START_ADDRESS, real_code)
        mu2.hook_add(UC_HOOK_CODE, hook_code)
        try:
            mu2.emu_start(START_ADDRESS, START_ADDRESS  + len(real_code))
        except:
            pass
       

    mu.reg_write(UC_X86_REG_RSP, STACK + 1 * 1024 * 1024)
    mu.mem_write(ADDRESS, X86_CODE64)
    mu.mem_write(START_ADDRESS, START_CODE)
    mu.hook_add(UC_HOOK_INSN, hookingSyscall, None, 1, 0, UC_X86_INS_SYSCALL)
    mu.emu_start(START_ADDRESS, START_ADDRESS + len(START_CODE))
    return True


if __name__ == '__main__':
    SERVER, PORT = ('13.112.146.72', 33333)
    s = remote(SERVER, PORT)
    
    while play():
        print(count)
        count = count + 1
        pass
