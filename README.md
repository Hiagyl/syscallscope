SyscallScope

SyscallScope is a lightweight system-call tracing and detection tool for Linux. It captures real-time syscall activity using eBPF/BPFtrace and processes events through a C-based detection engine to identify suspicious or anomalous behaviors.

Overview

SyscallScope detects:

Suspicious exec paths

Ransomware-like rapid write bursts

Directory scanning via getdents64

Abnormal chmod usage

Suspicious connect() attempts

Executable memory changes

Ptrace-based process manipulation

It provides real-time detection with minimal system overhead.

Features

Real-time syscall monitoring via BPFtrace

Structured SYS|key=value event pipeline

Per-PID state tracking

Rule-based detection engine

Timestamped alert reporting

C-based test generators for:

getdents64 directory bursts

connect() attempts

rapid write() activity

abusive chmod operations

System Requirements

OS: Linux (Ubuntu 20.04+, Debian, Kali, Arch) or WSL2 with eBPF

CPU: 64-bit

RAM: 4 GB

Dependencies:

BPFtrace

gcc

make

GNU Coreutils

Installation
Clone the Repository
git clone https://github.com/Hiagyl/syscallscope.git
cd syscallscope

Install Dependencies (Ubuntu Example)
sudo apt update
sudo apt install bpftrace coreutils build-essential make

Build and Run
Build Detection Engine
make build

Start BPFtrace Monitoring
make bpf

What These Commands Do

Compiles detection.c into syscall_detector

Runs syscalls.bt

Displays real-time syscall logs and triggers alerts

Troubleshooting
Permission Denied

Run with sudo:

sudo make bpf

Missing Tools

Check versions:

bpftrace --version
gcc --version
make --version

Makefile Errors

Ensure correct directory

Ensure filenames match

Try updating:

git pull

Repository Structure
syscallscope/
├── syscalls.bt
├── detection.c
├── Makefile
├── README.md
├── docs/
└── release/

Testing

The project includes reproducible simulators:

directory enumeration (getdents64)

network connect attempts

rapid-write ransomware load

suspicious chmod changes

Useful for validating detection accuracy.

Support

For issues or questions, contact:

Joshua Ticot

Myra Verde

Or open an Issue on GitHub.