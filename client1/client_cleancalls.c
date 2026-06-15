#include "dr_api.h"
#include "drmgr.h"

#define MAX_SS 10000
static app_pc shadow_stack[MAX_SS];
static int ss_top = 0;

/* Salva l'indirizzo di ritorno legittimo nello Shadow Stack */
static void push_to_shadow_stack(app_pc ret_addr) {
    if (ss_top < MAX_SS) {
        shadow_stack[ss_top++] = ret_addr;
    }
}

/* Legge lo stack dell'applicazione e lo confronta con lo Shadow Stack */
/* Riceve il valore del registro RSP (che è un puntatore alla memoria) */
static void check_return(app_pc app_rsp) {
    if (ss_top > 0) {
        app_pc expected = shadow_stack[--ss_top];
        
        app_pc actual_ret = NULL;
        dr_safe_read(app_rsp, sizeof(app_pc), &actual_ret, NULL);

        if (expected != actual_ret) {
            dr_fprintf(STDERR, "\n--------------------------------------------\n");
            dr_fprintf(STDERR, "[CLEAN CALLS] ATTENZIONE:\n");
            dr_fprintf(STDERR, "Tentativo di attacco bloccato.\n");
            dr_fprintf(STDERR, "Impossibile saltare a: %p\n", actual_ret);
            dr_fprintf(STDERR, "Terminazione processo in corso...\n");
            dr_fprintf(STDERR, "----------------------------------------------\n");
            dr_abort();
        }
    }
}

/* Strumentazione dei blocchi base */
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
                                             instr_t *instr, bool for_trace,
                                             bool translating, void *user_data) {
    
    if (instr_is_call(instr)) {
        app_pc next_instr = instr_get_app_pc(instr) + instr_length(drcontext, instr);
        dr_insert_clean_call(drcontext, bb, instr, (void *)push_to_shadow_stack, false, 1,
                             OPND_CREATE_INTPTR(next_instr));
    }
    else if (instr_is_return(instr)) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)check_return, false, 1,
                             opnd_create_reg(DR_REG_XSP));
    }
    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Shadow Stack - Clean Calls", "Progetto di SS");
    drmgr_init();
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}
