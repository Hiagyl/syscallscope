# Makefile

BPF=syscalls.bt
DETECTOR=syscall_detector
CC=gcc
CFLAGS=-std=c11 -O2 -Wall -Wextra

.PHONY: build bpf clean

# Build the detector
build:
	$(CC) $(CFLAGS) -o $(DETECTOR) syscall_detector.c

# Run BPF + detector together
bpf: build
# 	@echo "=== Starting BPF + Detector System ==="
	@sudo bpftrace -q $(BPF) | ./$(DETECTOR)

# Clean
clean:
	rm -f $(DETECTOR)
