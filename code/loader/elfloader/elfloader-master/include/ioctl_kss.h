#ifndef INSTRUM_MAP_H
#define INSTRUM_MAP_H

// DUPLICATE OF my_ioctl.h

#include "conf.h"

#ifdef IOCTL_INSTRUM_MAP
#include <linux/types.h>
#define INSTRUM_MAP _IOW('a', 'a', struct ioctl_data *)
/**
 * ioctl_data - Contiene le informazioni che verranno comunicate al Kernel Linux tramite la
 * ioctl del nodo in /proc. Consentono la costruzione della mappa di instrumentazione di livello
 * kernel per validare le richieste di simulazione.
 *
 * @call_num  : Numero di CALL instrumentate
 * @ret_num   : Numero di RET instrumentate
 * @call_array: Array di indirizzi di memoria virtuali delle CALL instrumentate
 * @ret_array : Array di indirizzi di memoria virtuali delle RET instrumentate
 * @start_text: Inizio della sezione .text che è stata instrumentata
 * @end_text  : Fine della sezione .text che è stata instrumentata
 */
struct ioctl_data {
    int call_num;
    int ret_num;
    unsigned long *call_array;
    unsigned long *ret_array;
    unsigned long start_text;
    unsigned long end_text;
};

#endif //IOCTL_INSTRUM_MAP

#ifdef LOG_SYSTEM
/**
 * log_system_info - Le informazioni necessarie per eseguire un corretto monitoraggio:
 * per generare degli eventi leggibili e per costruire il nome del file di log associato
 * al thread in esecuzione.
 *
 * @memory_mapped_base: Base di caricamento del nuovo programma
 * @id_user           : Identificativo utente associato al nuovo programma da lanciare
 * @program_name      : Nome dell'eseguibile di cui è istanza il nuovo processo
 * @len               : Lunghezza del nome
 */
typedef struct log_system_info {
    unsigned long memory_mapped_base;
    int id_user;
    char *program_name;
    size_t len;
} log_system_info;

#define SECURITY_METADATA _IOW('b', 'b', log_system_info *)
#else
#define SECURITY_METADATA _IO('b', 'b')
#endif //LOG_SYSTEM

#endif
