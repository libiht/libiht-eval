////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ca_nx.c
//  Description   : This is a sample program that detects if instrumentation
//                  tools are detecting the code is trying to execute code on a
//                  non-executable page.
//
//   Author : Thomason Zhao
//

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "malware.h"
#include "utils.h"

//
// Global variables

const char *progname = "sample_ca_nx";
const char *progdesc = "Sample adopts code cache / instruction artifacts detection - tries to execute code on a non-executable page";
int verbose = 0;
int debug = 0;

static volatile sig_atomic_t detected = -1;
static volatile sig_atomic_t catched_signal = -1;
static sigjmp_buf after_sigsev;

/**
 *  call 0x5
 *  push rax
 *  mov eax, 0x2a
 *  pop rax
 *  ret
 */
static const int assembly_size = 13;
static const unsigned char assembly[] = {0xE8, 0x00, 0x00, 0x00,
                                         0x00, 0x50, 0xB8,
                                         0x2A, 0x00, 0x00, 0x00, 0x58, 0xC3};

static void hdl(int sig) {
    detected = 0;

    catched_signal = sig;
    siglongjmp(after_sigsev, -1);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_nx
// Description  : Detect if instrumentation tools are detecting the code is
//                trying to execute code on a non-executable page
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_nx(void) {
    const long page_size = sysconf(_SC_PAGESIZE);

    if (sigsetjmp(after_sigsev, 1) != 0) {
        print_error("Received signal: %d\n", catched_signal);
        return detected;
    }

    struct sigaction act;
    memset(&act, 0x0, sizeof(act));

    act.sa_handler = hdl;
    act.sa_flags = SA_RESETHAND;

    if (sigaction(SIGSEGV, &act, NULL)) {
        print_error("Sigaction unsuccessful - %s\n", strerror(errno));
        return -1;
    }

    unsigned char *to_exec = malloc(page_size);
    if (to_exec == NULL) {
        print_error("Malloc with size %d unsuccessful - %s\n", page_size, strerror(errno));
        return -1;
    }

    memcpy(to_exec, assembly, assembly_size);

    asm volatile("call *%0" : : "m"(to_exec));

    return detected;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_nx() == 0) {
        print_verbose("Execution on non-executable page not detected.\n");
    } else {
        print_verbose("Execution on non-executable page detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}