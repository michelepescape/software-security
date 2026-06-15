#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

void test_ptrace() {
    printf("[TARGET] Esecuzione test ptrace(PTRACE_TRACEME)...\n");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        printf("[TARGET] [!] RILEVATO DEBUGGER: ptrace ha fallito! Deviazione flusso.\n");
    } else {
        printf("[TARGET] [✓] Successo: Nessun debugger rilevato tramite ptrace.\n");
    }
}

void test_proc_status() {
    printf("[TARGET] Esecuzione test /proc/self/status...\n");
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        perror("Apertura /proc fallita");
        return;
    }

    char line[256];
    int tracer_pid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            sscanf(line, "TracerPid:\t%d", &tracer_pid);
            printf("[TARGET] Stringa grezza letta: %s", line); // Mostra esattamente cosa legge
            break;
        }
    }
    fclose(f);

    if (tracer_pid > 0) {
        printf("[TARGET] [!] RILEVATO TRACER: TracerPid è %d! Evasione attivata.\n", tracer_pid);
    } else if (tracer_pid == 0) {
        printf("[TARGET] [✓] Successo: TracerPid è 0. Ambiente pulito.\n");
    } else {
        printf("[TARGET] [?] Errore nel parsing di TracerPid.\n");
    }
}

int main() {
    printf("[TARGET] Avvio del finto malware. PID: %d\n", getpid());
    printf("--------------------------------------------------\n");
    
    test_ptrace();
    printf("--------------------------------------------------\n");
    test_proc_status();
    
    printf("--------------------------------------------------\n");
    printf("[TARGET] Fine esecuzione.\n");
    return 0;
}
