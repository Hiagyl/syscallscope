# SyscallScope User Guide

## Overview
**SyscallScope** SyscallScope is a lightweight system-call tracing and detection tool for Linux. It captures real-time syscall activity using **eBPF/BPFtrace** and processes events through a C-based detection engine to identify suspicious or anomalous behaviors.

## Features

- **Real-time syscall monitoring** via BPFtrace
- **Structured SYS|key=value event pipeline**
- **Per-PID state tracking**
- **Rule-based detection engine**
- **Timestamped alert reporting**
- **C-based test generators** for:
  - `getdents64` directory bursts
  - `connect()` attempts
  - Rapid `write()` activity
  - Abusive `chmod` operations

## System Requirements
- Operating System: Windows 10/11 (with WSL) or Linux (Ubuntu 20.04+ recommended)  
- CPU: 64-bit  
- RAM: 4 GB minimum  
- Required Software:
  - **BPFtrace** (Apache 2.0 License)
  - **GNU Coreutils**
  - **gcc** (for compiling C code, if needed)
  - **make** (to run the Makefile)

## Installation

### Cloning the Repository
To get started, clone the GitHub repository:

git clone https://github.com/hiagyl/syscallscope.git
cd syscallscope

### Dependencies
Make sure all dependencies are installed. For example, on Ubuntu:

sudo apt update
sudo apt install bpftrace coreutils build-essential make
## Building and Running SyscallScope
SyscallScope uses a Makefile to compile and run the project. You do not need a container or virtual environment.

### Build and Run Both Files
To compile and run the main files, execute:

make build
make bpf

### These commands:

Compiles the source code
Runs the BPFtrace scripts
Displays real-time system call traces

## Troubleshooting
Permission Denied: Run with elevated privileges, e.g., sudo make bpf on Linux.

Missing Dependencies: Verify that BPFtrace, GNU Coreutils, gcc, and make are installed.

Makefile Errors: Ensure you are in the correct repository folder and that file paths match those in the Makefile.

## Support
For questions, issues, or bug reports, contact the project contributors:

Joshua Ticot
Myra Verde