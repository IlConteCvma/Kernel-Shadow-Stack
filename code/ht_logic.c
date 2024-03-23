#include "includes/kss_hashtable.h"

/**
 * delete_ht_item - Allows you to remove the element in the hash table associated with the current process.
 */
void delete_ht_item(void) {

    int found;
    ht_item *data;
    ht_item *target;


    found = 0;

    /* Resear the element to be removed in the hash table*/
    hash_for_each_possible(ht_tesi, data, ht_list_next, (unsigned long)current->mm) {
            
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
        if((void *)(target->lsi->program_name) != NULL)         kfree((void *)(target->lsi->program_name));
        if((void *)(target->lsi) != NULL)                       kfree((void *)target->lsi);

        /* Dealloco the element in the hash table */
        kfree((void *)target);

        pr_info("%s: [DELETE HASH TABLE ITEM] [%d] The element has been successfully eliminated\n", MOD_NAME, current->pid);

    } else {
        pr_err("%s: [ERRORE DELETE HASH TABLE ITEM] [%d] The element was not found in HT\n", MOD_NAME, current->pid);
    }
}