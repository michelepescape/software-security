#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

typedef struct {
    bool hook_ptrace_traceme;
    char *fgets_buf; /* Memorizza temporaneamente il puntatore al buffer durante la chiamata */
} per_thread_t;

static int tls_index;

static void thread_init_event(void *drcontext) {
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    data->hook_ptrace_traceme = false;
    data->fgets_buf = NULL;
    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void thread_exit_event(void *drcontext) {
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

/* --- HOOK PER FGETS --- */
/* Firma: char *fgets(char *s, int size, FILE *stream); */
static void wrap_fgets_pre(void *wrapcxt, void **user_data) {
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    
    /* Salviamo il puntatore al buffer 's' (primo argomento) nel TLS del thread 
     * per poterlo modificare al termine della funzione */
    data->fgets_buf = (char *)drwrap_get_arg(wrapcxt, 0);
}

static void wrap_fgets_post(void *wrapcxt, void *user_data) {
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);
    
    /* Se la funzione fgets ha restituito NULL, significa che la lettura è fallita o siamo a EOF */
    if (drwrap_get_retval(wrapcxt) == NULL || data->fgets_buf == NULL) {
        return;
    }

    char *buf = data->fgets_buf;
    data->fgets_buf = NULL; /* Reset immediato */

    /* Ispezioniamo in sicurezza il buffer in cui la libc ha appena scritto la riga */
    // char local_line[256];
    char local_line[512];
    size_t bytes_read = 0;
    
    /* Leggiamo una porzione di sicurezza per l'analisi */
    if (dr_safe_read(buf, sizeof(local_line) - 1, local_line, &bytes_read)) {
        local_line[bytes_read] = '\0';
        
        /* Cerchiamo il pattern TracerPid: */
        char *tracer_ptr = strstr(local_line, "TracerPid:");
        if (tracer_ptr != NULL) {
            dr_printf("[ANTI_EVASION] [fgets HOOK] Trovata stringa TracerPid nel buffer utente!\n");
            
            char *digit_ptr = tracer_ptr + 10;
            while (*digit_ptr == ' ' || *digit_ptr == '\t') {
                digit_ptr++;
            }
            
            if (*digit_ptr >= '0' && *digit_ptr <= '9') {
                /* Calcoliamo l'offset esatto nel buffer originale */
                ptrdiff_t offset = digit_ptr - local_line;
                
                /* Calcoliamo la lunghezza del PID numerico */
                size_t pid_len = 0;
                while (digit_ptr[pid_len] >= '0' && digit_ptr[pid_len] <= '9') {
                    pid_len++;
                }
                
                /* Prepariamo la stringa di spoofing */
                char patch_buf[64];
                // memset(patch_buf, ' ', sizeof(patch_buf));
                // patch_buf[0] = '0'; // Sostituiamo il primo carattere con '0', i restanti con spazi

                patch_buf[0] = '0';
                for (size_t i = 1; i < pid_len; i++) patch_buf[i] = ' ';
                
                if (pid_len < sizeof(patch_buf)) {
                    size_t bytes_written = 0;
                    /* Sovrascriviamo in sicurezza la memoria dell'applicazione */
                    dr_safe_write(buf + offset, pid_len, patch_buf, &bytes_written);
                    dr_printf("[ANTI_EVASION] Spoofing completato: TracerPid sovrascritto a 0.\n");
                }
            }
        }
    }
}

/* Intercettazione del caricamento della libc per fare il wrapping */
static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    if (strstr(mod->full_path, "libc.so") != NULL || strstr(mod->full_path, "libc-") != NULL) {
        app_pc fgets_pc = (app_pc)dr_get_proc_address(mod->handle, "fgets");
        if (fgets_pc != NULL) {
            if (drwrap_wrap(fgets_pc, wrap_fgets_pre, wrap_fgets_post)) {
                dr_printf("[ANTI_EVASION] Hook applicato con successo su fgets() di libc.\n");
            }
        }
    }
}

/* Manteniamo le syscall unicamente per l'anti-ptrace (che funziona già al 100%) */
static bool event_pre_syscall(void *drcontext, int sysnum) {
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);

    if (sysnum == SYS_ptrace) {
        reg_t request = dr_syscall_get_param(drcontext, 0);
        if (request == PTRACE_TRACEME) {
            dr_printf("[ANTI_EVASION] Intercettato ptrace(PTRACE_TRACEME)\n");
            data->hook_ptrace_traceme = true;
            dr_syscall_set_sysnum(drcontext, -1);
            return false;
        }
    }
    return true;
}

static void event_post_syscall(void *drcontext, int sysnum) {
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_index);

    if (sysnum == SYS_ptrace && data->hook_ptrace_traceme) {
        data->hook_ptrace_traceme = false;
        dr_syscall_result_info_t res_info;
        res_info.size = sizeof(res_info);
        res_info.succeeded = true;
        res_info.value = 0; 
        dr_syscall_set_result_ex(drcontext, &res_info);
    }
}

static void event_exit(void) {
    drmgr_unregister_module_load_event(module_load_event);
    drmgr_unregister_pre_syscall_event(event_pre_syscall);   
    drmgr_unregister_post_syscall_event(event_post_syscall); 
    drmgr_unregister_tls_field(tls_index);
    drwrap_exit();
    drmgr_exit();
    dr_printf("[ANTI_EVASION] Client rimosso correttamente.\n");
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Anti-Evasion Library Spoofer", "academic_project@domain.internal");
    
    if (!drmgr_init()) return;
    if (!drwrap_init()) return;

    tls_index = drmgr_register_tls_field();
    if (tls_index == -1) return;

    drmgr_register_thread_init_event(thread_init_event);
    drmgr_register_thread_exit_event(thread_exit_event);

    if (!drmgr_register_module_load_event(module_load_event)) return;

    void *drcontext = dr_get_current_drcontext();
    
    dr_module_iterator_t *iter = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(iter)) {
        module_data_t *mod = dr_module_iterator_next(iter);
        module_load_event(drcontext, mod, true);
        dr_free_module_data(mod);
    }
    dr_module_iterator_stop(iter);

    if (!drmgr_register_pre_syscall_event(event_pre_syscall) ||
        !drmgr_register_post_syscall_event(event_post_syscall)) {
        return;
    }

    dr_register_exit_event(event_exit);
    dr_printf("[ANTI_EVASION] Monitoraggio via API Hooking attivo (ptrace + fgets).\n");
}
