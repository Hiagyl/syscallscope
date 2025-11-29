// gcc ptrace_inject_demo.c -o ptrace_inject_demo
// sudo ./ptrace_inject_demo


#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

long inject_word = 0x4141414141414141; // "AAAAAAAA"

int main() {
    pid_t child = fork();

    if (child == 0) {
        // Child: Allocate buffer and stop
        static long buffer = 0x4242424242424242; // "BBBBBBBB"

        printf("[Child] PID = %d\n", getpid());
        printf("[Child] Buffer address = %p\n", (void*)&buffer);
        printf("[Child] Original buffer value: 0x%lx\n", buffer);

        raise(SIGSTOP); // Stop and wait for ptrace attach

        // After being modified
        printf("[Child] After ptrace modification: buffer = 0x%lx\n", buffer);

        _exit(0);
    }

    // Parent
    int status;
    waitpid(child, &status, 0);

    printf("\n[Parent] Attaching to child %d...\n", child);
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
        perror("ptrace attach");
        return 1;
    }

    waitpid(child, &status, 0);

    // Read child's buffer address
    printf("[Parent] Enter the child's buffer address shown above: ");
    unsigned long addr;
    scanf("%lx", &addr);

    printf("[Parent] Injecting 0x%lx into child memory...\n", inject_word);

    if (ptrace(PTRACE_POKEDATA, child, (void*)addr, (void*)inject_word) == -1) {
        perror("ptrace pokedata");
    } else {
        printf("[Parent] Injection complete.\n");
    }

    printf("[Parent] Detaching...\n");
    ptrace(PTRACE_DETACH, child, NULL, NULL);

    waitpid(child, NULL, 0);
    printf("[Parent] Child exited.\n");

    return 0;
}
