// synth_attack.c
// Compile: gcc -std=c11 -O2 -o synth_attack synth_attack.c
// Usage: ./synth_attack | ./syscall_detector

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void emit(const char *event) {
    puts(event);
    fflush(stdout);
    usleep(30000);  // 30ms tiny delay (feels real-time)
}

int main(void) {
    puts("=== Starting Synthetic Suspicious Activity ===");

    // ---------------------------------------------------------------------
    // 1. Normal baseline activity (should NOT trigger rules)
    // ---------------------------------------------------------------------
    emit("SYS|execve|pid=100|uid=1000|comm=bash|file=/bin/bash");
    emit("SYS|openat|pid=100|uid=1000|comm=bash|file=/etc/hostname");

    // ---------------------------------------------------------------------
    // 2. Rule 1: EXECVE Suspicious — execution from non-standard path
    // ---------------------------------------------------------------------
    emit("SYS|execve|pid=201|uid=1000|comm=runner|file=/tmp/.hidden_elf");
    emit("SYS|execve|pid=202|uid=1000|comm=runner|file=/dev/shm/app.run");

    // ---------------------------------------------------------------------
    // 3. Rule 2: MPROTECT with executable permission — possible injection
    // ---------------------------------------------------------------------
    emit("SYS|mprotect|pid=300|uid=1000|comm=injector|prot=PROT_EXEC");
    emit("SYS|mprotect|pid=300|uid=1000|comm=injector|prot=PROT_READ|PROT_WRITE|PROT_EXEC");

    // ---------------------------------------------------------------------
    // 4. Rule 3: PTRACE usage — debugging/injection
    // ---------------------------------------------------------------------
    emit("SYS|ptrace|pid=301|uid=1000|comm=traceutil|target=500|req=0");
    emit("SYS|ptrace|pid=301|uid=1000|comm=traceutil|target=501|req=1");

    // ---------------------------------------------------------------------
    // 5. Rule 4: CHMOD on system files
    // ---------------------------------------------------------------------
    emit("SYS|chmod|pid=400|uid=1000|comm=weirdproc|file=/etc/passwd|mode=777");
    emit("SYS|chmod|pid=400|uid=1000|comm=weirdproc|file=/usr/bin/sudo|mode=4755");



    // ---------------------------------------------------------------------
    // 7. Rule 6: UNLINK suspicious files
    // ---------------------------------------------------------------------
    emit("SYS|unlink|pid=600|uid=1000|comm=eraser|file=/var/log/auth.log");
    emit("SYS|unlink|pid=600|uid=1000|comm=eraser|file=/etc/ssh/ssh_host_rsa_key");

    // ---------------------------------------------------------------------
    // 8. Rule 7: GETDENTS64 burst — directory scraping
    // ---------------------------------------------------------------------
    for (int i = 0; i < 30; i++)
        emit("SYS|getdents64|pid=700|uid=1000|comm=scanner|fd=3|buf=0x12345678");

    // ---------------------------------------------------------------------
    // 9. Rule 8: Rapid writes — ransomware-like activity
    // ---------------------------------------------------------------------
    for (int i = 0; i < 40; i++)
        emit("SYS|write|pid=800|uid=1000|comm=cryptor|file=/home/user/docs/file.txt");

    // ---------------------------------------------------------------------
    // 10. Suspicious network connects: Rule extension
    // ---------------------------------------------------------------------
 
    emit("SYS|connect|pid=900|uid=1000|comm=client|sockfd=4|addr=23.129.64.210:9001");  // tor-like
    


    // ---------------------------------------------------------------------
    puts("=== Synthetic Suspicious Activity Ended ===");

    return 0;
}
