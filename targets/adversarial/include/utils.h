////////////////////////////////////////////////////////////////////////////////
//
//  File          : include/utils.h
//  Description   : This is the header file for the utility functions used by
//                  the sample malware program.
//
//   Author : Thomason Zhao
//

#ifndef _UTILS_H_
#define _UTILS_H_

//
// Global variables

extern const char *progname;
extern const char *progdesc;
extern int verbose;
extern int debug;

//
// Function prototypes

void process_command_line(int argc, char *argv[]);
void print_usage(void);
void print_error(const char *fmt, ...);
void print_debug(const char *fmt, ...);
void print_verbose(const char *fmt, ...);

#endif  // _UTILS_H_