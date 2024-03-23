
#include "includes/workqueue.h"


/**
 * flush_buffer_log - Viene eseguita dal Kernel Worker Daemon per riportare su file gli eventi
 * generati dai thread durante l'esecuzione oppure la copia della porzione di stack utente nel
 * caso in cui si sia verificato per la prima volta un evento di tipo SUC.
 *
 * @data: Puntatore agli argomenti
 */
void flush_buffer_log(unsigned long data) {

    param_kworker *pk;
    struct file *filp;
    unsigned char *buffer_log;
    char filename[512] = {0};
    unsigned long *user_stack;

    
    /* Recupero gli argomenti relativi al work che sta processando */
    pk = container_of((void *)data, param_kworker, the_work);

    /* Verifico se bisogna riportare un buffer di eventi oppure la copia dello stack utente corrotta */

    if(pk->type) {

        /* Recupero il puntatore alla porzione dello stack utente da riportare */
        user_stack = pk->user_stack;

        /* Costruisco il nome del file di LOG */
        snprintf(filename, 512, user_stack_path_format, pk->program_name, pk->id_user, pk->tid);

        /* Apro una sessione di I/O sul file di LOG */
        filp = init_log(filename);

        /* Riporto il contenuto del buffer su file */
        kernel_write(filp, user_stack, pk->user_stack_size, 0);

        /* Chiudo la sessione di I/O */
        close_log(filp);

        kfree((void *)user_stack);
        
    } else {

        /* Recupero il buffer di LOG contenente gli eventi da riportare */
        buffer_log = pk->buffer_log;

        /* Costruisco il nome del file di LOG */
        snprintf(filename, 512, log_path_format, pk->program_name, pk->id_user, pk->tid);

        /* Apro una sessione di I/O sul file di LOG */
        filp = init_log(filename);

        /* Riporto il contenuto del buffer su file */
        kernel_write(filp, buffer_log, strlen(buffer_log), 0);

        /* Chiudo la sessione di I/O */
        close_log(filp);

        /* Libero il buffer di LOG */
        free_pages((unsigned long)buffer_log, ORDER);
    }
}
