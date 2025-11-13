// syscall_detector.c
// Compile: gcc -std=c11 -O2 -Wall -Wextra -o syscall_detector syscall_detector.c
// Usage: ./synth_attack | ./syscall_detector
// Or:    sudo bpftrace your_script.bt | ./syscall_detector

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_PIDS 1024
#define MAX_COMM_LEN 64
#define MAX_PATH_LEN 512

typedef struct {
    int pid;
    char comm[MAX_COMM_LEN];
    int suspicious_count;
    time_t last_event;
} pid_state_t;

static pid_state_t pid_states[MAX_PIDS];
static int pid_count = 0;

// -----------------------------------------------
// Utility: Get or create PID state entry
// -----------------------------------------------
static pid_state_t* get_pid_state(int pid) {
    if (pid < 0) return NULL;
    for (int i = 0; i < pid_count; i++) {
        if (pid_states[i].pid == pid)
            return &pid_states[i];
    }

    if (pid_count < MAX_PIDS) {
        pid_states[pid_count].pid = pid;
        pid_states[pid_count].comm[0] = '\0';
        pid_states[pid_count].suspicious_count = 0;
        pid_states[pid_count].last_event = 0;
        pid_count++;
        return &pid_states[pid_count - 1];
    }

    return NULL; // table full
}

// -----------------------------------------------
// Utility: Print alert
// -----------------------------------------------
static void log_alert(const char *rule, pid_state_t *s, const char *details) {
    char timestr[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(timestr, sizeof(timestr), "%F %T", &tm);

    const char *comm = (s && s->comm[0]) ? s->comm : "-";
    int pid = (s) ? s->pid : -1;

    if (details && details[0])
        printf("%s [ALERT] %s | pid=%d comm=%s | %s\n", timestr, rule, pid, comm, details);
    else
        printf("%s [ALERT] %s | pid=%d comm=%s\n", timestr, rule, pid, comm);
    fflush(stdout);
}

// -----------------------------------------------
// Detection rules (same logic as before)
// -----------------------------------------------
void detect_event(const char *syscall, int pid, const char *comm, const char *file, const char *prot) {
    pid_state_t *s = get_pid_state(pid);
    if (!s) return;

    // safely copy comm
    if (comm && comm[0]) {
        strncpy(s->comm, comm, MAX_COMM_LEN - 1);
        s->comm[MAX_COMM_LEN - 1] = '\0';
    }

    time_t now = time(NULL);

    // Rule 1: Exec outside common paths
    if (strcmp(syscall, "execve") == 0) {
        const char *common1 = "/bin/";
        const char *common2 = "/usr/bin/";
        if (file && (strstr(file, common1) == NULL && strstr(file, common2) == NULL)) {
            char detail[256];
            snprintf(detail, sizeof(detail), "execve from unusual path: %s", file ? file : "-");
            log_alert("EXEC_OUTSIDE_COMMON_PATHS", s, detail);
        }
    }

    // Rule 2: mprotect with PROT_EXEC
    if (strcmp(syscall, "mprotect") == 0) {
        if (prot && strstr(prot, "PROT_EXEC")) {
            char detail[256];
            snprintf(detail, sizeof(detail), "mprotect with PROT_EXEC (prot=%s)", prot);
            log_alert("MPROTECT_PROT_EXEC", s, detail);
        }
    }

    // Rule 3: ptrace
    if (strcmp(syscall, "ptrace") == 0) {
        char detail[256];
        snprintf(detail, sizeof(detail), "ptrace called by process");
        log_alert("PTRACE_USED", s, detail);
    }

    // Rule 4: write to protected dirs
    if (strcmp(syscall, "write") == 0) {
        if (file && (strstr(file, "/etc/") || strstr(file, "/usr/bin/") || strstr(file, "/boot/"))) {
            char detail[256];
            snprintf(detail, sizeof(detail), "write to protected path: %s", file);
            log_alert("WRITE_PROTECTED_PATH", s, detail);
        }

        // Rule 5: rapid writes -> ransomware-like
        if (difftime(now, s->last_event) < 1.0) { // <1s between events
            s->suspicious_count++;
        } else {
            s->suspicious_count = 0;
        }
        s->last_event = now;

        if (s->suspicious_count > 10) {
            log_alert("RAPID_WRITES", s, "Rapid write pattern detected (possible ransomware)");
            s->suspicious_count = 0;
        }
    }
}

// -----------------------------------------------
// Robust parser: tokenize key=value tokens
// Expected input format:
//   SYS|event|k1=v1|k2=v2|...
// Example:
//   SYS|execve|pid=123|uid=1000|comm=vim|file=/home/user/a.out
// -----------------------------------------------
void process_line(char *line_in) {
    // copy the input because strtok_r modifies the buffer
    char buf[1024];
    strncpy(buf, line_in, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    // trim newline
    size_t L = strlen(buf);
    while (L && (buf[L - 1] == '\n' || buf[L - 1] == '\r')) { buf[--L] = '\0'; }

    if (L == 0) return;

    // must start with "SYS|"
    if (strncmp(buf, "SYS|", 4) != 0) return;

    char *saveptr = NULL;
    char *p = buf + 4;

    // first token: event name
    char *event = strtok_r(p, "|", &saveptr);
    if (!event) return;

    // initialize parsed fields
    int pid = -1;
    char comm[MAX_COMM_LEN] = {0};
    char file[MAX_PATH_LEN] = {0};
    char prot[64] = {0};

    // parse remaining tokens as key=value
    char *token;
    while ((token = strtok_r(NULL, "|", &saveptr)) != NULL) {
        if (strncmp(token, "pid=", 4) == 0) {
            pid = atoi(token + 4);
        } else if (strncmp(token, "comm=", 5) == 0) {
            // copy value after 'comm=' up to end
            strncpy(comm, token + 5, sizeof(comm) - 1);
            comm[sizeof(comm) - 1] = '\0';
        } else if (strncmp(token, "file=", 5) == 0) {
            strncpy(file, token + 5, sizeof(file) - 1);
            file[sizeof(file) - 1] = '\0';
        } else if (strncmp(token, "filename=", 9) == 0) {
            strncpy(file, token + 9, sizeof(file) - 1);
            file[sizeof(file) - 1] = '\0';
        } else if (strncmp(token, "pathname=", 9) == 0) {
            strncpy(file, token + 9, sizeof(file) - 1);
            file[sizeof(file) - 1] = '\0';
        } else if (strncmp(token, "prot=", 5) == 0) {
            strncpy(prot, token + 5, sizeof(prot) - 1);
            prot[sizeof(prot) - 1] = '\0';
        } else {
            // other keys ignored for now
        }
    }

    // Safety: if pid not found, ignore line
    if (pid < 0) {
        // optional: you may still want to handle pid 0 or missing pid differently
        return;
    }

    // call detector with parsed fields
    detect_event(event, pid, comm, file, prot);
}

// -----------------------------------------------
// Main
// -----------------------------------------------
int main(void) {
    char line[1024];
    printf("=== Syscall Detector Engine Active ===\n");

    // read forever until stdin is closed
    while (fgets(line, sizeof(line), stdin) != NULL) {
        process_line(line);
    }

    printf("=== Syscall Detector Engine Stopped ===\n");
    return 0;
}
