#ifndef HASHTAB_H
#define HASHTAB_H
#include <linux/hashtable.h>
#include "my_ioctl.h"
//#include "module-defines.h"

#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)
extern struct hlist_head ht_kss[8];

/**
 * HT_ITEM - Single element of the hash table
 *
 * @reference_counter: number of threads that have the reference to the information shared in this element
 * @mm_address: memory address of the mm structure associated with shared information
 * @instrum_Map_Address: pointer at the tentrous map for the process
 * @lsi: Puntor to the monitoring information for the process
 * @ht_list_next: pointer to the next element in the connected list of the hash table
 */
typedef struct ht_item {
    int reference_counter;
    unsigned long mm_address;
#ifdef IOCTL_INSTRUM_MAP
    unsigned long instrum_map_address;
#endif
#ifdef LOG_SYSTEM
    log_system_info *lsi;
#endif
    struct hlist_node ht_list_next;
} ht_item;
#endif //defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)

//Functions

extern void delete_ht_item(void);
extern int check_already_exists(char *program_name, int id_user);

#endif //HASHTAB_H
