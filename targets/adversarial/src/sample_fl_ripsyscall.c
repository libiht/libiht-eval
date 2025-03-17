////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_fl_ripsyscall.c
//  Description   : This is a sample program that detect whether rip value
//                  is saved in rcx after syscall instruction.
//
//   Author : Thomason Zhao
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "malware.h"
#include "utils.h"

//
// Macros
#define MAX_ULL(a, b) ((a) > (b) ? (a) : (b))
#define MIN_ULL(a, b) ((a) < (b) ? (a) : (b))

//
// Global variables

const char *progname = "sample_fl_ripsyscall";
const char *progdesc = "Sample adopts code cache / instruction artifacts detection - check whether rip value is saved in rcx after syscall instruction.";
int verbose = 0;
int debug = 0;

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_ripsyscall
// Description  : Detect whether rip value is saved in rcx after syscall
//                instruction.
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_ripsyscall(void) {
    unsigned long long rip = 0, saved_rip = 0;
    extern unsigned char ripsys_label[];
    unsigned long long page_size = sysconf(_SC_PAGESIZE);

    // As described in https://software.intel.com/en-us/articles/intel-sdm on
    // sysenter the rip value is saved in rcx so in the end it is restored
    // by sysexit. When executed in Pin on sysexit the value is not rip.
    asm volatile(
        ".global ripsys_label\n\t"
        "mov $0, %%rcx\n\t"
        "movq $0x27, %%rax\n\t"
        "syscall\n\t"
        "ripsys_label: \n\t"
        "leaq (%%rip), %0\n\t"
        "leaq (%%rcx), %1"
        : "=r"(rip), "=r"(saved_rip)
        :
        : "rax", "rcx");

    print_verbose("RIP: 0x%llx\n", rip);
    print_verbose("SavedRIP: 0x%llx\n", saved_rip);
    print_verbose("RIPLabel: %p\n", ripsys_label);

    if (saved_rip != (unsigned long long)ripsys_label ||
        MAX_ULL(rip, saved_rip) - MIN_ULL(rip, saved_rip) > page_size) {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_ripsyscall() == 0) {
        print_verbose("RIP saved in RCX after syscall not detected.\n");
    } else {
        print_verbose("RIP saved in RCX after syscall detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}