/**
 * A collection of useful definitions when writing eBPF.
 * Some of these were taken from https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h
 * Linux kernel sources: tools/lib/bpf/bpf_helpers.h tools/lib/bpf/libbpf_internal.h
 */

#ifndef HELPERS_H
#define HELPERS_H

#include "bpf_helpers.h"

/**
 * Aside from BPF helper calls and BPF tail calls, the BPF instruction did not arbitrary 
 * support functions -- as a result all functions need the inline macro.
 * Starting with Linux kernel 4.16 and LLVM 6.0 this restriction got lifted.
 * The typical inline keyword is only a hint whereas this is definitive.
 */
#define forced_inline __attribute__((always_inline))

/* 
 * helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/*
 * helper macro to make it simpler to print trace messages to
 * bpf_trace_printk.
 * ex. bpf_printk("BPF command: %d\n", op);
 * you can find the output in /sys/kernel/debug/tracing/trace_pipe
 * however it will collide with any othe rrunning process.
 */
#define bpf_printk(fmt, ...)                                                   \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})

/*
 * The __builtin_expect macros are GCC specific macros that use the branch prediction;
 * they tell the processor whether a condition is likely to be true,
 * so that the processor can prefetch instructions on the correct "side" of the branch.
 */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#endif
