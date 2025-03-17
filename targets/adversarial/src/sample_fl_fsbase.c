////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_fl_fsbase.c
//  Description   : This is a sample program that detects if fsbase value is
//                  the same using rdfsbase and prctl.
//
//   Author : Thomason Zhao
//

#include <asm/prctl.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <x86intrin.h>

#include "malware.h"
#include "utils.h"

//
// Global variables

const char *progname = "sample_fl_fsbase";
const char *progdesc = "Sample adopts code cache / instruction artifacts detection - detect if fsbase value is the same using rdfsbase and prctl.";
int verbose = 0;
int debug = 0;

static volatile sig_atomic_t detected = -1;
static volatile sig_atomic_t catched_signal = -1;
static sigjmp_buf after_sigill;

static void hdl(int sig) {
    detected = -1;

    catched_signal = sig;
    siglongjmp(after_sigill, -1);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_fsbase
// Description  : Detect if fsbase value is the same using rdfsbase and prctl.
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_fsbase(void) {
    if (sigsetjmp(after_sigill, 1) != 0) {
        print_error("Received signal: %d\n", catched_signal);
        return detected;
    }

    struct sigaction act;
    memset(&act, 0x0, sizeof(act));

    act.sa_handler = hdl;
    act.sa_flags = SA_RESETHAND;

    if (sigaction(SIGILL, &act, NULL)) {
        print_error("Sigaction unsuccessful - %s\n", strerror(errno));
        return -1;
    }

    unsigned long long rdfsbase = _readfsbase_u64();

    unsigned long long prctl_fsbase;
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, &prctl_fsbase) == -1) {
        print_error("arch_prctl GET_FS failed - %s\n", strerror(errno));
        return -1;
    }

    print_verbose("rdfsbase: 0x%lx\n", rdfsbase);
    print_verbose("prctl: 0x%lx\n", prctl_fsbase);

    return rdfsbase != prctl_fsbase ? -1 : 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_fsbase() == 0) {
        print_verbose("Change of fsbase value not detected.\n");
    } else {
        print_verbose("Change of fsbase value detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}