#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct linux_dirent64 {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

int main() {
    printf("[TEST] Trigger getdents64 burst\n");

    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    char buf[4096];

    // Rapid burst of getdents64 calls
    for (int i = 0; i < 200; i++) { // adjust number to trigger rule
        long nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread == -1) {
            perror("getdents64");
            break;
        }
    }

    close(fd);
    printf("[DONE] getdents64 burst finished.\n");
    return 0;
}
