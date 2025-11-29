#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    const char *target = "/usr/bin/sudo";
    mode_t mode = 04755;  // setuid + rwxr-xr-x

    printf("[*] Attempting chmod(%s, %o)\n", target, mode);

    if (chmod(target, mode) == -1) {
        printf("[!] chmod failed: %s\n", strerror(errno));
        return 1;
    }

    printf("[+] chmod succeeded!\n");
    return 0;
}
