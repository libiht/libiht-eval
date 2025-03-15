////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ea_mapname.c
//  Description   : This is a sample program that detects mapped files name for
//                  known DBI framework values.
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

const char *progname = "sample_template";
const char *progdesc = "Sample template malware program";
int verbose = 0;
int debug = 0;

static const char *pinbin = "pinbin";
static const char *dynamorio = "dynamorio";
static const char *dynistAPI = "dyninstAPI";
static const char *vgpreload = "vgpreload";

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_mapped_files
// Description  : Detect mapped files name for known DBI framework values.
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_mapped_files(void) {
    int detected = 0;
    procmaps_iterator maps_it;
    procmaps_struct *maps;

    if (pmparser_parse(-1, &maps_it) != 0) {
        print_error("Failed to parse the memory maps\n");
        return -1;
    }

    while ((maps = pmparser_next(&maps_it)) != NULL) {
        char *pathname = maps->pathname;
        if (strstr(pathname, pinbin) != NULL ||
            strstr(pathname, dynamorio) != NULL ||
            strstr(pathname, dynistAPI) != NULL ||
            strstr(pathname, vgpreload) != NULL) {
            detected = -1;
            print_verbose("DBI framework detected: %s\n", pathname);
            break;
        }
    }

    pmparser_free(&maps_it);
    return detected;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_mapped_files() == 0) {
        print_verbose("DBI framework in mapped files not detected.\n");
    } else {
        print_verbose("DBI framework in mapped files detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}