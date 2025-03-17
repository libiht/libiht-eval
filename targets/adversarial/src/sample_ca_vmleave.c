////////////////////////////////////////////////////////////////////////////////
//
//  File          : src/sample_ca_vmleave.c
//  Description   : This is a sample program that detects known code patterns
//                  (VMLeave) for anti-instrumentation techniques.
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

const char *progname = "sample_ca_vmleave";
const char *progdesc = "Sample adopts environmental artifact detection - checks for known code patterns (VMLeave) for anti-instrumentation techniques.";
int verbose = 0;
int debug = 0;

static const int pin_vmleave_size = 60;
static const unsigned char pin_vmleave[] = {
    0x9D,                    // popf
    0x48, 0x8B, 0x38,        // mov     rdi, [rax]
    0x48, 0x8B, 0x70, 0x08,  // mov     rsi, [rax+8]
    0x48, 0x8B, 0x68, 0x10,  // mov     rbp, [rax+10h]
    0x48, 0x8B, 0x60, 0x18,  // mov     rsp, [rax+18h]
    0x48, 0x8B, 0x58, 0x20,  // mov     rbx, [rax+20h]
    0x48, 0x8B, 0x50, 0x28,  // mov     rdx, [rax+28h]
    0x48, 0x8B, 0x48, 0x30,  // mov     rcx, [rax+30h]
    0x4C, 0x8B, 0x40, 0x40,  // mov     r8, [rax+40h]
    0x4C, 0x8B, 0x48, 0x48,  // mov     r9, [rax+48h]
    0x4C, 0x8B, 0x50, 0x50,  // mov     r10, [rax+50h]
    0x4C, 0x8B, 0x58, 0x58,  // mov     r11, [rax+58h]
    0x4C, 0x8B, 0x60, 0x60,  // mov     r12, [rax+60h]
    0x4C, 0x8B, 0x68, 0x68,  // mov     r13, [rax+68h]
    0x4C, 0x8B, 0x70, 0x70,  // mov     r14, [rax+70h]
    0x4C, 0x8B, 0x78, 0x78   // mov     r15, [rax+78h]
};

static const int qbdi_vmleave_size = 113;
static const unsigned char qbdi_vmleave[] = {
    0x9D,                                      // popf
    0x48, 0x8B, 0x05, 0x3B, 0x12, 0x00, 0x00,  // mov    rax, QWORD PTR [rip+0x123b]
    0x48, 0x8B, 0x1D, 0x3C, 0x12, 0x00, 0x00,  // mov    rbx, QWORD PTR [rip+0x123c]
    0x48, 0x8B, 0x0D, 0x3D, 0x12, 0x00, 0x00,  // mov    rcx, QWORD PTR [rip+0x123d]
    0x48, 0x8B, 0x15, 0x3E, 0x12, 0x00, 0x00,  // mov    rdx, QWORD PTR [rip+0x123e]
    0x48, 0x8B, 0x35, 0x3F, 0x12, 0x00, 0x00,  // mov    rsi, QWORD PTR [rip+0x123f]
    0x48, 0x8B, 0x3D, 0x40, 0x12, 0x00, 0x00,  // mov    rdi, QWORD PTR [rip+0x1240]
    0x4C, 0x8B, 0x05, 0x41, 0x12, 0x00, 0x00,  // mov    r8, QWORD PTR [rip+0x1241]
    0x4C, 0x8B, 0x0D, 0x42, 0x12, 0x00, 0x00,  // mov    r9, QWORD PTR [rip+0x1242]
    0x4C, 0x8B, 0x15, 0x43, 0x12, 0x00, 0x00,  // mov    r10, QWORD PTR [rip+0x1243]
    0x4C, 0x8B, 0x1D, 0x44, 0x12, 0x00, 0x00,  // mov    r11, QWORD PTR [rip+0x1244]
    0x4C, 0x8B, 0x25, 0x45, 0x12, 0x00, 0x00,  // mov    r12, QWORD PTR [rip+0x1245]
    0x4C, 0x8B, 0x2D, 0x46, 0x12, 0x00, 0x00,  // mov    r13, QWORD PTR [rip+0x1246]
    0x4C, 0x8B, 0x35, 0x47, 0x12, 0x00, 0x00,  // mov    r14, QWORD PTR [rip+0x1247]
    0x4C, 0x8B, 0x3D, 0x48, 0x12, 0x00, 0x00,  // mov    r15, QWORD PTR [rip+0x1248]
    0x48, 0x8B, 0x2D, 0x49, 0x12, 0x00, 0x00,  // mov    rbp, QWORD PTR [rip+0x1249]
    0x48, 0x8B, 0x25, 0x4A, 0x12, 0x00, 0x00   // mov    rsp, QWORD PTR [rip+0x124a]

};

static const int num_patterns = 2;
static const unsigned char *needles[] = {pin_vmleave, qbdi_vmleave};
static const size_t needles_sizes[] = {pin_vmleave_size, qbdi_vmleave_size};

////////////////////////////////////////////////////////////////////////////////
//
// Function     : detect_vmleave
// Description  : Detect known code patterns (VMLeave) for anti-instrumentation
//                techniques.
//
// Inputs       : None
// Outputs      : 0 if not detected, -1 if detected

int detect_vmleave(void) {
    int detected = 0;
    void *found = NULL;
    procmaps_iterator maps_it;
    procmaps_struct *maps;

    if (pmparser_parse(-1, &maps_it) < 0) {
        print_error("Failed to parse the memory maps.\n");
        return -1;
    }

    while ((maps = pmparser_next(&maps_it)) != NULL) {
        if (maps->is_r &&
            strstr(maps->pathname, progname) == NULL &&
            strstr(maps->pathname, "[vvar]") == NULL) {
            for (int i = 0; i < num_patterns; i++) {
                if ((found = memmem(maps->addr_start, maps->length, needles[i], needles_sizes[i])) != NULL) {
                    detected += 1;
                    print_verbose("Found VMLeave pattern in %s at %p\n", maps->pathname, found);
                }
            }
        }
    }

    pmparser_free(&maps_it);
    print_verbose("Detected %d VMLeave patterns.\n", detected);
    return detected > 1 ? -1 : 0;
}

int main(int argc, char *argv[]) {
    process_command_line(argc, argv);

    // Some detection anti-instrumentation techniques implemenation
    if (detect_vmleave() == 0) {
        print_verbose("VMLeave pattern not detected.\n");
    } else {
        print_verbose("VMLeave pattern detected.\n");
        exit(1);
    }

    shellcode();
    return 0;
}