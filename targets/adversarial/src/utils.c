////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/utils.c
//  Description   : This is the utility functions for the sample malware
//                  program.
//
//   Author : Thomason Zhao
//

#include "utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////////
//
// Function     : process_command_line
// Description  : This function processes the command line arguments
//
// Inputs       : argc - the number of command line arguments
//                argv - the array of command line arguments
// Outputs      : None

void process_command_line(int argc, char *argv[]) {
    int c;
    while ((c = getopt(argc, argv, "vdh")) != -1) {
        switch (c) {
            case 'v':
                verbose = 1;
                break;
            case 'd':
                debug = 1;
                break;
            case 'h':
                print_usage();
                break;
            default:
                print_usage();
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : print_usage
// Description  : This function prints a usage message
//
// Inputs       : None
// Outputs      : None

void print_usage(void) {
    printf("Usage: %s [-vdh]\n", progname);
    printf("%s\n\n", progdesc);
    printf("   -v  verbose mode\n");
    printf("   -d  debug mode\n");
    printf("   -h  help\n");
    exit(1);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : print_error
// Description  : This function prints an error message
//
// Inputs       : fmt - the format string for the error message
// Outputs      : None

void print_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : print_debug
// Description  : This function prints a debug message
//
// Inputs       : fmt - the format string for the debug message
// Outputs      : None

void print_debug(const char *fmt, ...) {
    if (debug) {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "DEBUG: ");
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : print_verbose
// Description  : This function prints a verbose message
//
// Inputs       : fmt - the format string for the verbose message
// Outputs      : None

void print_verbose(const char *fmt, ...) {
    if (verbose) {
        va_list args;
        va_start(args, fmt);
        fprintf(stdout, "VERBOSE: ");
        vfprintf(stdout, fmt, args);
        va_end(args);
    }
}