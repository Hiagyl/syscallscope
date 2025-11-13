// synth_attack.c
// Compile: gcc -std=c11 -O2 -o synth_attack synth_attack.c
// Usage: ./synth_attack | ./syscall_detector

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // for sleep()
#include <string.h>

void emit(const char *event) {
    puts(event);
    fflush(stdout);
    sleep(0); // wait 1 second between events; change to sleep(0) for no delay
}

int main(void) {
    puts("=== Starting Synthetic Suspicious Activity ===");

    // Normal events
    emit("SYS|execve|pid=200|uid=1000|comm=bash|file=/bin/bash");
    emit("SYS|openat|pid=200|uid=1000|comm=bash|file=/etc/hosts");

    // Suspicious: exec outside system dirs
    emit("SYS|execve|pid=201|uid=1000|comm=unknown|file=/tmp/hacktool");

    // Possible injection: mprotect with PROT_EXEC
    emit("SYS|mprotect|pid=201|uid=1000|comm=unknown|prot=PROT_EXEC");

    // ptrace usage
    emit("SYS|ptrace|pid=300|uid=1000|comm=injector|target=123|req=0");

    // Writing to system dirs
    // emit("SYS|write|pid=400|uid=1000|comm=editor|file=/etc/passwd");

    // Ransomware-like behavior: rapid file writes
    for (int i = 0; i < 15; i++) {
        emit("SYS|write|pid=500|uid=1000|comm=cryptor|file=/home/user/docs/file.txt");
    }

    puts("=== Synthetic Suspicious Activity Ended ===");
    return 0;
}
