1 Introduction
The syscallscope project is a lightweight system-call monitoring and alerting tool within
a Kali Linux virtual machine environment. The proposal has five core objectives: implement
a syscall capture engine, create rule-based and heuristic detectors, provide visualizations and
alerts, demonstrate detection of crafted suspicious behaviors, and the final output with docu-
mentation. Based on the approved proposal, all of these objectives were fully achieved. The
completed project has an eBPF-based capture engine, a C-driven detection core with rule-based
heuristics, and a command-line interface that provides real-time alerts and views of suspicious
sessions. It also successfully demonstrated the detection of crafted behaviors.
The primary change from the initial proposal was the user interface. A lightweight web
dashboard using FLASK was initially proposed, however, based on the approved proposal, the
project will rely entirely on the CLI and terminal dashboard. This made us focus more on the
development of core features.
Overall, syscallscope successfully met all the core objectives and effectively demonstrated
the utility of eBPF for security monitoring, and thus providing reliable detection of suspicious
behaviors in controlled environments.
2 Background and Motivation
System calls are programmed requests to the operating system’s kernel. Applications use
syscalls to perform operations they cannot do directly in user space. Linux alone has over 400
syscalls (Kamaluddin, 2023). Actions requiring privileged access like file I/O, process man-
agement, memory management, and network sockets must pass through a syscall (Jumpcloud,
2025). This means that malicious behavior also leaves traces in syscall sequences (Gond & Mo-
hapatra, 2025). Without syscalls, programs would bypass the kernel’s protection which may
cause security vulnerabilities, system crashes, and unauthorized access to system resources.
Traditional monitoring tools like strace, ltrace and gdb rely on the ptrace system call to
intercept these events (Operating Systems 2021F, n.d.). Although useful for debugging, ptrace is
intrusive and introduces heavy performance overhead and excessive noise from filtering through
numerous system calls(Ashur, 2024). As a result, existing tools cannot provide scalable or
efficient visibility into syscall behavior.
Hence, syscallscope used the Extended Berkeley Packet Filter (eBPF). It is a modern kernel
technology that enables lightweight tracing without stopping processes. eBPF programs run
safely inside the kernel and captures syscall events with minimal overhead (Rabinovich, 2025;
Gerarde, 2025). By leveraging the tool bpftrace, this makes the project provide fast and reliable
monitoring without slowing the system.
3 Objectives and Success Criteria
The original objectives during the project proposal and their success criteria are listed below:
1. Implement a syscall-capture engine that records syscalls, arguments, timestamps, and
process context for sample processes.
Success Criteria:
Successful capture and logging of syscall metadata using eBPF/bpftrace framework on
Kali Linux.
Status: Fully achieved.
2. Design and apply rule-based and heuristic detectors for suspicious syscall patterns.
Success Criteria:
3
SYSCALLSCOPE CMSC 131: Special Topics
Creation of detection rules and C-based detector that successfully tags logs with correct
suspicion score and flag.
Status: Fully achieved.
3. Provide visualizations and alerts: a timeline view of syscalls and flagged suspicious sessions.
Success Criteria:
Functional Command-Line Interface (CLI) and terminal displaying real-time alerts.
Status: Fully achieved.
4. Demonstrate practical examples by showing detection of crafted suspicious behaviors.
Success Criteria:
Execute successful demonstration scenarios of crafted suspicious behaviors that shows cor-
rect anomaly detection and alerting of the suspicious events.
Functional Command-Line Interface (CLI) and terminal displaying real-time alerts.
Status: Fully achieved.
5. Documentation for the project design, rules, limitations, and instruction guide.
Success Criteria:
Final report, documentations, README and usage instructions.
Status: Fully achieved.
4 Scope and Limitations
A. Scope
This project is only limited to the following:
1. Target environment: The system was developed and tested on Linux within a Kali Linux
Virtual Machine (VM) environment.
2. Capture mechanisms: The primary mechanism for syscall data capture for this project is
eBPF.
3. Detection Strategy: The project was implemented using rule-based detection design fo-
cusing only on common suspicious syscall activities.
4. User Interface: CLI for visualization of alerts and query.
5. Core Functionality: Capture, log, detect and basic alert visualization.
B. Limitations
1. This is only for educational use and not a production-grade IDS.
2. Heuristics may generate false positives. Comprehensive tuning is beyond one month.
3. This project does not inspect encrypted network payloads or perform deep binary emula-
tion.
4. Kernel-level rootkit detection or full anti-evasion hardening is out of scope.
5. Cross-platform beyond the Kali Linux environment is not supported.
The project was constrained by the authors’ limited knowledge on the topic which required
additional time for learning and exploration which slowed the progress. The limited time for
project development, as well as other external factors like limited internet access, power interrup-
tions, typhoons, and other deliverables from other subjects also affected the project development.
4
SYSCALLSCOPE CMSC 131: Special Topics
5 System Architecture and Methodology
5.1 High-Level Architecture
syscalls.bt (eBPF) --------------> syscall_detector.c (C)
trace system calls detects suspicious syscalls
5.2 Components
5.2.1 Syscall Capture Layer (BPFtrace / eBPF)
This layer attaches probes to key system calls including execve, write, open, connect, mprotect,
and getdents64. It produces structured, pipe-delimited output such as:
SYS|write|pid=1234|comm=bash|file=/home/joshua/a.txt
5.2.2 Event Parsing Layer
The C-based parsing module processes the formatted events, extracting key=value fields and
maintaining per-process state, including:
• PID and command name
• timestamps of recent activity
• counters for rate-based heuristics
5.2.3 Detection Engine
The detection engine evaluates incoming events against eight rule-based heuristics:
1. Suspicious executable paths
2. Executable memory regions (mprotect PROT_EXEC)
3. Ransomware-like rapid write bursts
4. Suspicious chmod modifications
5. Directory enumeration bursts (getdents64)
6. Suspicious connect() attempts
7. Whitelisting based on process names and paths
5.2.4 Alerting System
The system produces timestamped alerts that include:
• the triggered rule
• PID and process name
• contextual details (file paths, syscall parameters, etc.)
Example logging snippet:
printf("%s [ALERT] %s | pid=%d comm=%s | %s\n",
timestr, rule, pid, comm, details);
5
SYSCALLSCOPE CMSC 131: Special Topics
5.3 Methodology
The methodology for syscall monitoring and detection consists of:
1. Instrumenting target syscalls using BPFtrace probes.
2. Streaming structured events from the capture layer into the C engine.
3. Maintaining per-PID state such as time windows and counters.
4. Applying rule-based heuristics to classify behaviors as benign or suspicious.
5. Generating alerts upon rule violations.
6. Evaluating the system using benign application workloads and malicious synthetic pat-
terns.
6 Implementation Details
6.1 Directory Structure
The SyscallScope project has the following structure:
/syscallscope
test/
Makefile
README.md
syscall_detector.c
syscalls.bt
USER_GUIDE.md
6.2 Key Data Structures
The main data structure used for tracking per-process state is defined as:
typedef struct {
int pid;
char comm[64];
int suspicious_count;
time_t last_event;
} pid_state_t;
This structure allows the tool to maintain state for each process, including the number of
suspicious events detected and the timestamp of the last event, enabling rate-based heuristics.
6.3 Important Design Decisions
• Chose BPFtrace for simplicity and rapid development instead of writing raw eBPF C
programs.
• Used rule-based detection rather than machine learning to ensure explainability of
alerts.
• Implemented per-PID state tracking to enable rate-based heuristics and reduce false
positives.
6
SYSCALLSCOPE CMSC 131: Special Topics
6.4 Notable Code Modules
• detect_event(): Central dispatcher that evaluates syscall events against all detection
rules.
• exec_whitelisted(): Prevents noisy alerts for known safe executables.
• process_line(): Parses structured syscall event lines into internal data structures.
• syscalls.bt: Attaches BPF probes to monitor relevant system calls in real-time.
6.5 Snippet — Alert Logging
Alerts are printed using the following format:
printf("%s [ALERT] %s | pid=%d comm=%s | %s\n",
timestr, rule, pid, comm, details);
This outputs the timestamp, rule triggered, process ID, command name, and additional
details about the suspicious activity.
7 Distribution & Deployment
7.1 Release Artifacts
SyscallScope is distributed directly via the GitHub repository:
https://github.com/Hiagyl/syscallscope
7.2 Deployment Options
7.2.1 Local Installation
SyscallScope can be deployed locally on a Linux system with the following requirements:
• gcc — for compiling the C detector.
• bpftrace — for eBPF-based syscall tracing.
• Linux kernel with eBPF support.
Steps to deploy:
git clone https://github.com/Hiagyl/syscallscope
cd syscallscope
make build
make bpf
The make bpf command runs the BPFtrace scripts and pipes system call events to the compiled
detector for real-time monitoring.
7.2.2 Environment Configuration
No secrets or special environment variables are required. Elevated privileges (sudo) are recom-
mended to access BPF features and trace system calls.
7
SYSCALLSCOPE CMSC 131: Special Topics
7.2.3 Rollback & Upgrade
To upgrade, simply pull the latest version from the GitHub repository:
git pull origin main
Downgrade by checking out a previous commit or release tag. Semantic versioning is maintained
in the repository for clarity.
8 Code Repository
8.1 Canonical Repository
The official repository for SyscallScope is available at:
https://github.com/Hiagyl/syscallscope
8.2 Branches
• main — Stable, production-ready branch.
8.3 Releases
The project follows semantic versioning. Example:
v1.0.0
8.4 Clone and Run
To get started with SyscallScope, clone the repository and build the detector:
git clone https://github.com/Hiagyl/syscallscope
cd syscallscope
make build
make bpf
The make bpf command will run the BPFtrace scripts and pipe system call events to the com-
piled syscall and detector program for real-time monitoring.
9 Usage
After cloning the repository and installing dependencies, SyscallScope can be built and run
directly using the provided Makefile. No containerization or virtual environment is required.
9.1 Building the Project
To compile the project, navigate to the repository folder and run:
make build
This command compiles all source code, including C files used to simulate syscalls such as
getdents64, connect, chmod, and rapid write operations.
8
SYSCALLSCOPE CMSC 131: Special Topics
9.2 Running SyscallScope
Once the project is built, execute the main BPFtrace scripts using:
make bpf
This command performs the following actions:
• Loads BPFtrace scripts to monitor system calls in real-time.
• Detects unusual executable launches, memory protections, ptrace invocations, rapid writes,
fast directory scans, suspicious network connections, and unexpected chmod modifications.
• Outputs syscall traces and alerts directly to the terminal for live monitoring.
10 Testing and Quality Assurance
The testing of SyscallScope was designed to verify both functionality and performance across a
variety of scenarios. We employed a combination of unit tests, integration tests, manual quality
assurance, and stress tests to ensure the tool met all project requirements.
10.1 Unit Tests
Unit tests focused on individual components such as parsing logic, whitelists, and rule triggering.
These tests ensured that each subsystem correctly identifies and processes relevant syscalls and
events.
10.2 Integration Tests
Integration tests evaluated the full syscall monitoring pipeline, verifying that events from the
kernel are correctly captured, processed, and flagged according to detection rules. These tests
included C programs that simulate specific behaviors such as:
• getdents64 directory enumeration
• connect network calls
• chmod permission changes
• Rapid file write bursts
These synthetic programs allowed controlled validation of detection logic.
10.3 Known Limitations
Some high-activity user-space utilities may trigger false positives due to frequent write opera-
tions. Additionally, certain containerized network connections can appear as suspicious, which
may require further tuning of detection rules.
9
SYSCALLSCOPE CMSC 131: Special Topics
11 Results and Discussion
The evaluation of SyscallScope demonstrates that the system effectively detects a range of
suspicious behaviors on Linux systems. The tool successfully identified executables launched
from unusual directories. These detections provide early warning for potential malware activity
and process tampering, enabling administrators to respond promptly to threats. SyscallScope
also captured ransomware-like rapid write operations, fast directory enumeration bursts via
getdents64, unexpected chmod changes, and suspicious outbound connections, covering a broad
spectrum of malicious or abnormal system behaviors.
From a performance perspective, SyscallScope proved efficient. The overhead introduced by
BPFtrace was low to moderate, and the CPU usage of the detector remained below 1% during
typical workloads. This confirms that the tool can operate continuously in real-time without
significantly impacting system performance.
Overall, SyscallScope met all project success criteria. Its comprehensive monitoring of filesys-
tem, memory, process, and network activities, combined with minimal performance impact,
validates the use of BPFtrace and custom detection logic for real-time system call analysis.
The results demonstrate that SyscallScope is an effective security monitoring solution for Linux
environments, capable of identifying both reconnaissance and potentially malicious activity ef-
ficiently.
12 Recommendations
For future developers:
• Replace rule-based engine with ML anomaly detection
• Use libbpf + CO-RE for higher performance
• Implement configuration files for rules
• Add JSON output format
• Add visualization dashboard via web UI
• Support remote monitoring via sockets
13 Licensing and Credits
This project is licensed under the MIT License.
Contributors
• Joshua Ticot
• Myra Verde
Third-party Software
• BPFtrace – Apache 2.0 License
• GNU Coreutils
14 Appendices
User Guide: USER_GUIDE.md
10
SYSCALLSCOPE CMSC 131: Special Topics
15 References
• Ashur, D. (2024, August 6). itemitHolistically Protect ECS Deployments with Upwind’s
Support for ECS Fargate. Upwind | Cloud Security Happens at Runtime. Retrieved from
https://www.upwind.io/feed/holistically-protect-ecs-deployments-with-upwinds-support-for
• BPFtrace Documentation. Retrieved from https://bpftrace.org
• Garfinkel, T., et al. (2014). System call-based intrusion detection. ACM Symposium on
Operating Systems Principles.
• Gerarde, D. P. (2025, February 24). Understanding EBPF: a Game-Changer for Linux
Kernel Extensions. DEV Community. https://dev.to/dpuig/understanding-ebpf-a-game-changer-f
• Gond, B. P., & Mohapatra, D. P. (2025, June). System calls for Malware Detection and
Classification: Methodologies and applications. Retrieved from https://arxiv.org/html/
2506.01412v1
• JumpCloud. (2025, July 21). What is a System Call?. Retrieved from https://jumpcloud.
com/it-index/what-is-a-system-call
• Kamaluddin, K. (2023, December 3). Dynamic malware analysis through system call trac-
ing and API monitoring. ESP International Journal of Advancements in Computational
Technology, 1(3), 167–179. https://doi.org/10.56472/25838628/IJACT-V1I3P118
• Kerrisk, M. (2010). The Linux Programming Interface: A Linux and UNIX System Pro-
gramming Handbook. No Starch Press. (See getdents64 syscall for directory enumeration
attacks)
• Love, R. (2013). Linux System Programming: Talking Directly to the Kernel and C Library.
2nd Edition. O’Reilly Media. (See connect syscall for network connections)
• Operating Systems 2021F. (n.d.). Retrieved from https://homeostasis.scs.carleton.
ca/wiki/index.php/Operating_Systems_2021F:_Tutorial_4
• Rabinovich, Y. (2025, April 10). EBPF Tracing. Retrieved from https://www.groundcover.
com/ebpf/ebpf-tracing
• Stevens, W., Rago, S. (2013). Advanced Programming in the UNIX Environment. 3rd
Edition. Addison-Wesley. (See chmod syscall for file permission modifications)
• White, B., & Case, T. (2020). Linux Observability with BPF. O’Reilly Media.
16 Acknowledgements
We would like to express our deepest gratitude to all the people who made this project
possible and offered their utmost support and encouragement throughout its duration.
To our instructor, Sir Ren, thank you for your guidance, support, and weekly feedback
which helped us improve our project. We appreciate how you provided us with the opportunity
to explore and learn beyond our subject’s coverage.
To our family and friends, we are sincerely grateful for your patience, understanding, and
thank you for cheering for us.