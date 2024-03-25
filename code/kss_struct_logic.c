#include "includes/module-defines.h"
#include "includes/kss_struct.h"

/**
* Check_integrity_Security_Medata - verifies the integrity of the safety metadata and the Kernel level stack
 * Original of the current thread.To verify the integrity of the Origianle Kernel level Stack it is used
 * A Magic Number.
 *
 * @nd_of_stack: pointer at the base of the original thread original kernel kernel
 *
 * @return: return the value 1 if all checks end with success;Otherwise, it returns the value 0.
 */
int check_integrity_security_metadata(unsigned long *end_of_stack) {

    security_metadata *sm;


    /*Recovery the reference to security metadata            */
    GET_SECURITY_METADATA(end_of_stack, sm);

    /* I perform checks on the content of the original kernel stack */
    if((end_of_stack[0] == (unsigned long)MAGIC_NUMBER) && (end_of_stack[2] == (unsigned long)MAGIC_NUMBER) && ((void *)sm != NULL)) {
        return 1;
    }

    return 0;
}

/**
 * Check_error_finish_task_Switch_hook - Check if there was an error in the allocation of the metadata structure
 * Safety during the hook on the Finish_task_Switch ().
 *
 * @nd_of_stack: pointer at the base of the original thread original kernel kernel
 *
 * @return: return the value 1 if the error has occurred;Otherwise it returns the value 0.
 */
int check_errore_finish_task_switch_hook(unsigned long *end_of_stack) {

    security_metadata *sm;


    /* Recovery the reference to security metadata                              */
    GET_SECURITY_METADATA(end_of_stack, sm);

    /* I check if it was not possible to allocate the structure of the safety metadata */
    if(end_of_stack[0] == (unsigned long)MAGIC_NUMBER &&
       end_of_stack[2] == (unsigned long)MAGIC_NUMBER &&
       (void *)sm == NULL) {
        pr_err("%s: [CHECK ERROR FINISH TASK SWITCH] [%d] The structure of security metadata has not been allocated\n",
        MOD_NAME,
        current->pid);
        return 1;

    }

    /* I check the consistency of the Kernel level Stack                            */
    if(end_of_stack[0] == (unsigned long)MAGIC_NUMBER &&
       end_of_stack[2] == (unsigned long)MAGIC_NUMBER &&
       (void *)sm != NULL) {

        if((void *)(sm->free_items) == NULL || (void *)(sm->kernel_stack) == NULL) {
            pr_err("%s: [CHECK ERROR FINISH TASK SWITCH] [%d] The Kernel level stack was not correctly allocated\n",
            MOD_NAME,
            current->pid);
            return 1;
        }

    }

    return 0;
}

/**
 * Check_error_Security_Medata - Check if there has been an error in the allocation of the metadata structure
 * security during the Security_Medata command.
 *
 * @nd_of_stack: pointer at the base of the original thread original kernel kernel
 *
 * @return: return the value 1 if the error has occurred;Otherwise it returns the value 0.
 */
int check_error_security_metadata(unsigned long *end_of_stack) {

    security_metadata *sm;


    /* Recovery the reference to security metadata           */
    GET_SECURITY_METADATA(end_of_stack, sm);

    if(end_of_stack[0] == (unsigned long)MAGIC_NUMBER &&
       end_of_stack[2] == (unsigned long)MAGIC_NUMBER &&
       (void *)sm == NULL) {
        return 1;
    }

    return 0;
}