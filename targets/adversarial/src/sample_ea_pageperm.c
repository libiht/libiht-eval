////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ea_pageperm.c
//  Description   : This is a sample program that detects if there are pages
//                  with rwx permission.
//
//   Author : Thomason Zhao
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "malware.h"
#include "pmparser.h"
#include "utils.h"

//
// Global variables

const char *progname = "sample_ea_pageperm";
const char *progdesc = "Sample adopts environmental artifact detection - checks for page with rwx permission.";
int verbose = 0;
int debug = 0;

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_pageperm
// Description  : Detects if there are pages with rwx permission
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_pageperm(void) {
    int rwx = 0;
    procmaps_iterator maps_it;
    procmaps_struct *maps;

    if (pmparser_parse(-1, &maps_it) != 0) {
        print_error("Failed to parse the memory maps.\n");
        return -1;
    }

    while ((maps = pmparser_next(&maps_it)) != NULL) {
        if (maps->is_r && maps->is_w && maps->is_x) {
            rwx++;
        }
    }

    pmparser_free(&maps_it);
    print_verbose("Number of pages with rwx permission: %d\n", rwx);
    return rwx > 2 ? -1 : 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_pageperm() == 0) {
        print_verbose("Page with rwx permission not detected.\n");
    } else {
        print_verbose("Page with rwx permission detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}