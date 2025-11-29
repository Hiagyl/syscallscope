#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    printf("[TEST] chmod on /etc/hosts\n");
    int result = chmod("/etc/hosts", 0777);
    perror("chmod");
    return 0;
}
