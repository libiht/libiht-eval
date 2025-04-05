////////////////////////////////////////////////////////////////////////////////
//
//  File          : drcftrace.c
//  Description   : This file mainly references the cbrtrace.c and instrcalls.c
//                  file from DynamoRIO sample tools. This will trace all
//                  control flow transitions in the application and log them to
//                  a file. The file will be named drcftrace.<pid>.<tid>.log and
//                  will be located in the client library directory. The log
//                  will contain the following information:
//                  - The address of the instruction that caused the transition
//                  - The address of the target instruction
//                  Link: https://dynamorio.org/API_samples.html
//
//   Author : Thomason Zhao
//

#include "dr_api.h"
#include "drmgr.h"
#include "utils.h"

static client_id_t client_id;

static int tls_idx;

/* Clean call for the cbr */
static void
at_cbr(app_pc inst_addr, app_pc targ_addr, int taken)
{
    void *drcontext = dr_get_current_drcontext();
    file_t log = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
    /* We only log the taken branch */
    if (taken) {
        dr_fprintf(log, "" PFX " => " PFX "\n", inst_addr, targ_addr);
    }
}

/* Clean call for the control flow transitions */
static void
at_cftrans(app_pc inst_addr, app_pc targ_addr)
{
    void *drcontext = dr_get_current_drcontext();
    file_t log = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
    dr_fprintf(log, "" PFX " => " PFX "\n", inst_addr, targ_addr);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    if (instr_is_call_direct(instr)) {
        dr_insert_call_instrumentation(drcontext, bb, instr, (void *)at_cftrans);
    }
    else if (instr_is_cbr(instr)) {
        dr_insert_cbr_instrumentation(drcontext, bb, instr, (void *)at_cbr);
    }
    else if (instr_is_ubr(instr)) {
        dr_insert_ubr_instrumentation(drcontext, bb, instr, (void *)at_cftrans);
    }
    else if (instr_is_mbr(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (void *)at_cftrans,
                                     SPILL_SLOT_1);
    }
    
    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    file_t log;
    log =
        log_file_open(client_id, drcontext, NULL /* using client lib path */, "drcftrace",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
    DR_ASSERT(log != INVALID_FILE);
    drmgr_set_tls_field(drcontext, tls_idx, (void *)(ptr_uint_t)log);
}

static void
event_thread_exit(void *drcontext)
{
    log_file_close((file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx));
}

static void
event_exit(void)
{
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'drcftrace' exiting");
#ifdef SHOW_RESULTS
    if (dr_is_notify_on())
        dr_fprintf(STDERR, "Client 'drcftrace' exiting\n");
#endif
    if (!drmgr_unregister_bb_insertion_event(event_app_instruction) ||
        !drmgr_unregister_tls_field(tls_idx))
        DR_ASSERT(false);
    drmgr_exit();
}

DR_EXPORT
void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Sample Client 'drcftrace'",
                       "http://dynamorio.org/issues");
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'drcftrace' initializing");

    drmgr_init();

    client_id = id;
    tls_idx = drmgr_register_tls_field();

    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT(false);

#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
#    ifdef WINDOWS
        dr_enable_console_printing();
#    endif /* WINDOWS */
        dr_fprintf(STDERR, "Client 'drcftrace' is running\n");
    }
#endif /* SHOW_RESULTS */
}
