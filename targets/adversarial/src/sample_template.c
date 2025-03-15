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

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    // TODO

    shellcode();
    return 0;
}