////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ro_jitlib.c
//  Description   : This is a sample program that detects JIT library overhead.
//
//   Author : Thomason Zhao
//

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#include "malware.h"
#include "utils.h"

//
// Global variables

const char *progname = "sample_ro_jitlib";
const char *progdesc = "Sample adopts JIT compiler runtime overhead detection - check the time overhead when JIT compile on library loading";
int verbose = 0;
int debug = 0;

static const int num_loads = 5;
static const int linux_common_libs_num = 5;
static const char *linux_common_libs[] = {
    "libpthread.so.0",   // POSIX threads for multi-threading
    "libutil.so.1",      // Utility functions (e.g., for terminal handling)
    "libcrypt.so",       // Cryptography functions
    "libselinux.so.1",   // SELinux support for security contexts
    "libpcre.so.3",      // Perl Compatible Regular Expressions
    "libm.so.6",         // Math library (e.g., for sin, cos, sqrt)
    "libdl.so.2",        // Dynamic loading of shared libraries
    "librt.so.1",        // Realtime extensions (timers, signals)
    "libnsl.so.1",       // Network services library (legacy, sometimes needed)
    "libc.so.6",         // Standard C library (core system functions)
    "libstdc++.so.6"     // GNU Standard C++ Library for C++ applications
};

////////////////////////////////////////////////////////////////////////////////
//
// Function     : load_unload_libs
// Description  : Load and unload libraries
//
// Inputs       : libnames - the names of libraries
//                libnum - the number of libraries
// Outputs      : 0 if successful, -1 if failure

int load_unload_libs(const char *libnames[], int libnum) {
    for (int i = 0; i < libnum; i++) {
        void *handle = dlopen(libnames[i], RTLD_NOW);
        if (handle == NULL) {
            print_error("Failed to load library %s: %s\n", libnames[i], dlerror());
            return -1;
        }
        if (dlclose(handle) != 0) {
            print_error("Failed to unload library %s: %s\n", libnames[i], dlerror());
            return -1;
        }
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_jitlib_overhead
// Description  : Detect JIT library overhead by loading and unloading libs.
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_jitlib_overhead(void) {
    unsigned long long start[num_loads], end[num_loads];

    for (int i = 0; i < num_loads; i++) {
        start[i] = __rdtsc();
        if (load_unload_libs(linux_common_libs, linux_common_libs_num) != 0) {
            print_error("Failed to load/unload libraries\n");
            return -1;
        }
        end[i] = __rdtsc();
    }

    for (int i = 0; i < num_loads; i++) {
        print_verbose("JIT lib overhead %d: %llu\n", i, end[i] - start[i]);
        if (i > 0) {
            double overhead = (double)(end[i] - start[i]) / (end[i - 1] - start[i - 1]);
            print_verbose("JIT lib overhead ratio %d: %f\n", i, overhead);
            if (overhead < 0.36) {
                return -1;
            }
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_jitlib_overhead() ==  0) {
        print_verbose("JIT library overhead not detected\n");
    } else {
        print_verbose("JIT library overhead detected\n");
        exit(1);
    }

    shellcode();
    return 0;
}