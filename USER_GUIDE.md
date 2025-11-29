# SyscallScope User Guide

## 1. Introduction
**SyscallScope** is a system call tracing and analysis tool that allows users to monitor and inspect the behavior of processes in real time.  
This guide explains how to install, build, and run SyscallScope from source.

## 2. System Requirements
- Operating System: Windows 10/11 (with WSL) or Linux (Ubuntu 20.04+ recommended)  
- CPU: 64-bit  
- RAM: 4 GB minimum  
- Required Software:
  - **BPFtrace** (Apache 2.0 License)
  - **GNU Coreutils**
  - **gcc** (for compiling C code, if needed)
  - **make** (to run the Makefile)

## 3. Installation

### Cloning the Repository
To get started, clone the GitHub repository:

git clone https://github.com/hiagyl/syscallscope.git
cd syscallscope

### Dependencies
Make sure all dependencies are installed. For example, on Ubuntu:

sudo apt update
sudo apt install bpftrace coreutils build-essential make
## 4. Building and Running SyscallScope
SyscallScope uses a Makefile to compile and run the project. You do not need a container or virtual environment.

### Build and Run Both Files
To compile and run the main files, execute:

make build
make bpf

### These commands:

Compiles the source code
Runs the BPFtrace scripts
Displays real-time system call traces

## 5. Troubleshooting
Permission Denied: Run with elevated privileges, e.g., sudo make bpf on Linux.

Missing Dependencies: Verify that BPFtrace, GNU Coreutils, gcc, and make are installed.

Makefile Errors: Ensure you are in the correct repository folder and that file paths match those in the Makefile.

## 6. Support
For questions, issues, or bug reports, contact the project contributors:

Joshua Ticot
Myra Verde