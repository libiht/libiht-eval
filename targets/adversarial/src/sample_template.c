////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_template.c
//  Description   :
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
// Global variables

const char *progname = "sample_template";
const char *progdesc = "Sample template malware program";
int verbose = 0;
int debug = 0;

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_xxx
// Description  : Detect xxx (anti-instrumentation technique)
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_xxx(void) {
    // TODO: Detailed implementation
    return 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_xxx() == 0) {
        print_verbose("xxx not detected.\n");
    } else {
        print_verbose("xxx detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}