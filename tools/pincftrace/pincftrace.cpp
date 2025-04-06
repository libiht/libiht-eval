////////////////////////////////////////////////////////////////////////////////
//
//  File          : pincftrace.cpp
//  Description   : This file mainly references the calltrace.cpp file from PIN
//                  sample tools. This will trace all control flow transitions
//                  in the application and log them to a file. The file will be
//                  named pincftrace.log and will be located in the client
//                  library directory. The log will contain the following
//                  information:
//                  - The address of the instruction that caused the transition
//                  - The address of the target instruction
//                  Link: https://software.intel.com/sites/landingpage/pintool/docs/98869/Pin/doc/html/index.html
//
//   Author : Thomason Zhao
//

#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
using std::hex;
using std::ios;
using std::string;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "pincftrace.log", "specify trace file name");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a control flow trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

string invalid = "invalid_rtn";

/* ===================================================================== */

VOID do_cftrans(ADDRINT inst_addr, ADDRINT targ_addr, BOOL taken)
{
    if (!taken) return;
    /* We only log the taken branch */
    TraceFile << hex << inst_addr << " => " << hex << targ_addr << endl;
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID* v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS tail = BBL_InsTail(bbl);

        if (INS_IsControlFlow(tail))
        {
            INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_cftrans),
                            IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
                            IARG_BRANCH_TAKEN, IARG_END);
        }
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v)
{
    TraceFile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    TraceFile.open(KnobOutputFile.Value().c_str());

    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

