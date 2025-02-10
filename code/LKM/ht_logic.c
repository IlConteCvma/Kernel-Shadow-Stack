#include "includes/kss_hashtable.h"
#include "includes/driver-core.h"

/*
 * This hash table is used to maintain the references to information that is shared among the threads of
 * the same process.The threads of the same process share the Memory Management data structure located a
 * A specific memory address.This memory address can be used to search for information
 * relating to the various threads.A reference couunter is used that keeps track of the number of threads they have
 * recovered the references to shared information.When the counter becomes zero then it is possible to remove
 * the element from the hash table.
 */
DEFINE_HASHTABLE(ht_kss, 3);

/**
 * delete_ht_item - Allows you to remove the element in the hash table associated with the current process.
 */
void delete_ht_item(void) {

    int found;
    ht_item *data;
    ht_item *target;


    found = 0;

    /* Resear the element to be removed in the hash table*/
    hash_for_each_possible(ht_kss, data, ht_list_next, (unsigned long)current->mm) {
            
        /* I check if the current element is associated with the current thread mm */
        if((unsigned long)data->mm_address == (unsigned long)current->mm) {
            target = data;
            found = 1;
            break;
        }
     }

    if(found == 1) {

        /* Remove the element from the hash table */
        hash_del(&(target->ht_list_next));

        /* Dealloco the shared data structures associated with the process */
        #ifdef LOG_SYSTEM
        if((void *)(target->lsi->program_name) != NULL)         kfree((void *)(target->lsi->program_name));
        if((void *)(target->lsi) != NULL)                       kfree((void *)target->lsi);
        #endif

        /* Dealloco the element in the hash table */
        kfree((void *)target);

        pr_info("%s: [DELETE HASH TABLE ITEM] [%d] The element has been successfully eliminated\n", MOD_NAME, current->pid);

    } else {
        pr_err("%s: [ERRORE DELETE HASH TABLE ITEM] [%d] The element was not found in HT\n", MOD_NAME, current->pid);
    }
}

/**
 * Check_ALENEDY_EXISTS - I check if the identification sent by the user has already been used for a
 * Past process.
 *
 *
 *
 * @return: return the value 0 if the identification of the process can be used;otherwise,
 * remain the value 1.
 */
#ifdef LOG_SYSTEM
int check_already_exists(char *program_name, int id_user) {
    
    int bkt;
    int found;
    ht_item *data;

    found = 0;

    hash_for_each(ht_kss, bkt, data, ht_list_next) {
        if(!strcmp(data->lsi->program_name, program_name) && ((data->lsi)->id_user == id_user)) {
            found = 1;
            break;
         }
    }
    
    return found;
}
#endif