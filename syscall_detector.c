// syscall_detector.c
// Compile: gcc -std=c11 -O2 -Wall -Wextra -o syscall_detector syscall_detector.c
// Usage: ./synth_attack | ./syscall_detector
// Or:    sudo bpftrace syscalls.bt | ./syscall_detector

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

/* ================================================
   PID STATE TABLE
   ================================================ */
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

/* ================================================
   LOG ALERT
   ================================================ */
static void log_alert(const char *rule, pid_state_t *s, const char *details) {
    char timestr[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(timestr, sizeof(timestr), "%F %T", &tm);

    const char *comm = (s && s->comm[0]) ? s->comm : "-";
    int pid = (s) ? s->pid : -1;

    if (details && details[0])
        printf("%s [ALERT] %s | pid=%d comm=%s | %s\n",
               timestr, rule, pid, comm, details);
    else
        printf("%s [ALERT] %s | pid=%d comm=%s\n",
               timestr, rule, pid, comm);

    fflush(stdout);
}

/* ================================================
   EXEC PATH WHITELIST
   ================================================ */
static int exec_whitelisted(const char *file) {
    if (!file || !file[0]) return 1;

    const char *whitelist[] = {
        "/bin/",
        "/usr/bin/",
        "/sbin/",
        "/usr/sbin/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/snap/bin/",
        "/opt/",
        "/usr/share/",
        NULL
    };

    for (int i = 0; whitelist[i] != NULL; i++) {
        if (strncmp(file, whitelist[i], strlen(whitelist[i])) == 0)
            return 1;
    }

    // Allow user home directory
    if (strncmp(file, "/home/", 6) == 0)
        return 1;

    return 0;
}

/* ================================================
   PROCESS WRITE WHITELIST
   These processes write frequently but harmlessly.
   ================================================ */
static int write_process_whitelisted(const char *comm) {
    const char *proc_whitelist[] = {
        "gdbus",
        "dbus-daemon",
        "sshd",
        "sshd-session",
        "node",
        "code",
        "code-oss",
        "firefox",
        "chrome",
        "chromium",
        "xfce4-panel-gen",
        "xfce4-session",
        "systemd",
        "pulseaudio",
        "pipewire",
        "gvfsd",
        NULL
    };

    if (!comm || !comm[0]) return 0;

    for (int i = 0; proc_whitelist[i] != NULL; i++) {
        if (strcmp(comm, proc_whitelist[i]) == 0)
            return 1;
    }

    return 0;
}

/* ================================================
   DETECTION LOGIC
   ================================================ */
void detect_event(const char *syscall, int pid, const char *comm,
                  const char *file, const char *prot) {

    pid_state_t *s = get_pid_state(pid);
    if (!s) return;

    if (comm && comm[0]) {
        strncpy(s->comm, comm, MAX_COMM_LEN - 1);
        s->comm[MAX_COMM_LEN - 1] = '\0';
    }

    time_t now = time(NULL);

    /* =======================================================
     * RULE 1: Exec outside common paths
     * ======================================================= */
    if (strcmp(syscall, "execve") == 0) {
        if (!exec_whitelisted(file)) {
            char detail[256];
            snprintf(detail, sizeof(detail),
                     "execve from unusual path: %s", file ? file : "-");
            log_alert("EXEC_OUTSIDE_COMMON_PATHS", s, detail);
        }
    }

    /* =======================================================
     * RULE 2: mprotect(PROT_EXEC)
     * ======================================================= */
    if (strcmp(syscall, "mprotect") == 0) {
        if (prot && strstr(prot, "PROT_EXEC")) {
            char detail[256];
            snprintf(detail, sizeof(detail),
                     "mprotect with PROT_EXEC (prot=%s)", prot);
            log_alert("MPROTECT_PROT_EXEC", s, detail);
        }
    }

    /* =======================================================
     * RULE 3: ptrace
     * ======================================================= */
    if (strcmp(syscall, "ptrace") == 0) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "ptrace used by process");
        log_alert("PTRACE_USED", s, detail);
    }

    /* =======================================================
     * RULE 4 + 5: Rapid writes (ransomware-like)
     * ======================================================= */
    if (strcmp(syscall, "write") == 0) {

        /* Skip harmless processes */
        if (write_process_whitelisted(s->comm))
            goto END_RULES;

        /* Skip noise directories */
        if (file && (
            strstr(file, "/proc/") ||
            strstr(file, "/dev/") ||
            strstr(file, "/run/") ||
            strstr(file, "/sys/") ||
            strstr(file, "/tmp/") ||
            strstr(file, "socket:") ||
            strstr(file, "pipe:")
        )) {
            goto END_RULES;
        }

        double diff = difftime(now, s->last_event);

        if (diff < 0.3)
            s->suspicious_count++;
        else
            s->suspicious_count = 0;

        s->last_event = now;

        if (s->suspicious_count > 50) {
            log_alert("RAPID_WRITES", s,
                      "Rapid write pattern detected (possible ransomware)");
            s->suspicious_count = 0;
        }
    }

    /* =======================================================
     * RULE 6: chmod on sensitive paths
     * ======================================================= */
    if (strcmp(syscall, "chmod") == 0 ||
        strcmp(syscall, "fchmod") == 0 ||
        strcmp(syscall, "fchmodat") == 0) {

        if (file &&
            !(strstr(file, "/home/") || strstr(file, "/tmp/") ||
              strstr(file, "/var/tmp/") || strstr(file, "/dev/"))) {

            char detail[256];
            snprintf(detail, sizeof(detail),
                     "chmod on non-user path: %s", file);
            log_alert("CHMOD_SUSPICIOUS_PATH", s, detail);
        }
    }

    /* =======================================================
     * RULE 7: Rapid getdents64 (directory scanning)
     * ======================================================= */
    if (strcmp(syscall, "getdents64") == 0) {

        double diff = difftime(now, s->last_event);

        if (diff < 0.2)
            s->suspicious_count++;
        else
            s->suspicious_count = 0;

        s->last_event = now;

        if (s->suspicious_count > 40) {
            log_alert("RAPID_DIR_ENUMERATION", s,
                      "Burst of getdents64 calls (directory scanning)");
            s->suspicious_count = 0;
        }
    }

    /* =======================================================
     * RULE 8: Suspicious connect()
     * ======================================================= */
    if (strcmp(syscall, "connect") == 0) {

        if (file &&
            !(strstr(file, "127.0.0.1") ||
              strstr(file, "localhost") ||
              strstr(file, ":80") ||
              strstr(file, ":443"))) {

            char detail[256];
            snprintf(detail, sizeof(detail),
                     "connect to unusual address");
            log_alert("SUSPICIOUS_CONNECT", s, detail);
        }
    }

END_RULES:
    return;
}


/* ================================================
   INPUT PARSER (key=value)
   ================================================ */
void process_line(char *line_in) {
    char buf[1024];
    strncpy(buf, line_in, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    

    size_t L = strlen(buf);
    while (L && (buf[L - 1] == '\n' || buf[L - 1] == '\r')) buf[--L] = '\0';
    if (L == 0) return;

    if (strncmp(buf, "SYS|", 4) != 0) return;

    char *saveptr = NULL;
    char *p = buf + 4;

    char *event = strtok_r(p, "|", &saveptr);
    if (!event) return;

    int pid = -1;
    char comm[MAX_COMM_LEN] = {0};
    char file[MAX_PATH_LEN] = {0};
    char prot[64] = {0};

    char *token;
    while ((token = strtok_r(NULL, "|", &saveptr)) != NULL) {

        if (strncmp(token, "pid=", 4) == 0)
            pid = atoi(token + 4);

        else if (strncmp(token, "comm=", 5) == 0)
            strncpy(comm, token + 5, sizeof(comm) - 1);

        else if (strncmp(token, "file=", 5) == 0)
            strncpy(file, token + 5, sizeof(file) - 1);
        else if (strncmp(token, "addr=", 5) == 0)
            strncpy(file, token + 5, sizeof(file) - 1);

        else if (strncmp(token, "filename=", 9) == 0)
            strncpy(file, token + 9, sizeof(file) - 1);

        else if (strncmp(token, "pathname=", 9) == 0)
            strncpy(file, token + 9, sizeof(file) - 1);

        else if (strncmp(token, "prot=", 5) == 0)
            strncpy(prot, token + 5, sizeof(prot) - 1);
    }

    if (pid < 0) return;

    detect_event(event, pid, comm, file, prot);
}

/* ================================================
   MAIN LOOP
   ================================================ */
int main(void) {
    char line[1024];
    printf("=== Syscall Detector Engine Active ===\n");

    while (fgets(line, sizeof(line), stdin) != NULL)
        process_line(line);

    printf("=== Syscall Detector Engine Stopped ===\n");
    return 0;
}
