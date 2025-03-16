////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ca_smc.c
//  Description   : This is a sample program that detects if instrumentation
//                  tools are detecting the self-modifying code (SMC) technique.
//
//   Author : Thomason Zhao
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "malware.h"
#include "utils.h"

//
// Global variables

const char *progname = "sample_ca_smc";
const char *progdesc = "Sample adopts code cache / instruction artifacts detection - checks for SMC detection";
int verbose = 0;
int debug = 0;

////////////////////////////////////////////////////////////////////////////////
//
// Function     : change_page_permissions
// Description  : Change the permissions of a page
//
// Inputs       : addr - the address of the page
//                prot - the new permissions
// Outputs      : 0 if successful, -1 if failed

int change_page_permissions(void *addr, int prot) {
    // Move the pointer to the page boundary
    addr -= (unsigned long)addr % sysconf(_SC_PAGE_SIZE);
    if (mprotect(addr, sysconf(_SC_PAGE_SIZE), prot) == -1) {
        print_error("mprotect failed.\n");
        return -1;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_smc
// Description  : Detect if the self-modifying code (SMC) technique is detected
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_smc(void) {
    volatile int change_me = 0;
    extern unsigned char mov_label[];
    unsigned char *mov_instr_addr = mov_label + 0x1;

    if (change_page_permissions((void *)mov_instr_addr, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        print_error("Failed to change page permissions.\n");
        return -1;
    }

    *mov_instr_addr = 0x00;
    asm volatile(
        ".global mov_label\n\t"
        "mov_label: \n\t"
        "mov $1, %%eax\n\t"
        "mov %%eax, %0"
        : "=r"(change_me)
        :
        : "rax");

    if (change_page_permissions((void *)mov_instr_addr, PROT_READ | PROT_EXEC) == -1) {
        print_error("Failed to change page permissions.\n");
        return -1;
    }

    print_verbose("change_me = %d\n", change_me);
    return change_me == 1 ? -1 : 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_smc() == 0) {
        print_verbose("Self-modifying code (SMC) not detected.\n");
    } else {
        print_verbose("Self-modifying code (SMC) detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}