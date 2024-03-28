//#include "includes/module-defines.h"
//#include "includes/kss_struct.h"
#include "includes/utils.h"
#include "includes/logging.h"
#include "includes/dirver-core.h"


#ifdef SINGLE_ADDRESS_TIMER
unsigned long average_time_one_byte = 0;
unsigned long total_time_one_byte = 0;
unsigned long counter_one_byte = 0;
#endif //SINGLE_ADDRESS_TIMER

#ifdef BLOCK_ADDRESS_TIMER
unsigned long average_time_block = 0;
unsigned long total_time_block = 0;
unsigned long counter_block = 0;
#endif //BLOCK_ADDRESS_TIMER

#ifdef TIMER_COMPARE_RET_ADDR
unsigned long average_time_compare = 0;
unsigned long total_time_compare = 0;
unsigned long counter_compare = 0;
int guard = 0;
#endif

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
int check_error_finish_task_switch_hook(unsigned long *end_of_stack) {

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


/**
 * get_free_item - Recovery a free stack element to store new validation information.
 *
 * @end_of_stack: base of the original stack kernel of the current thread
 *
 * @return: I return the null value if there is no free stack element;otherwise, I return
 * The pointer at the free stack element that has been recovered.
 */
stack_item *get_free_item(unsigned long *end_of_stack) {

    int index;
    security_metadata *sm;
    free_item *old_head;


    /* Recovery the pointer to security metadata                                                       */
    GET_SECURITY_METADATA(end_of_stack, sm);

    /* I check if the connected list of free stack elements is empty                                */
    if(sm->first_free_item == NULL) {
        return NULL;
    }

    /* I exploit the correspondence that exists between the elements of the two free_items buffer [i] and kernel_stack [i] */
    index = ((unsigned long)sm->first_free_item - (unsigned long)sm->free_items)/sizeof(free_item);

    /* I check the validity of the index that has been recovered                                            */
    if(index < 0) {
        pr_err("%s: [ERROR GET FREE ITEM] [%d] Value %d of the index is not valid\n", MOD_NAME, current->pid, index);
        kill_process();
    }

    old_head = sm->first_free_item;

    /* Removal of the element at the top of the connected list                                                */
    sm->first_free_item = (sm->first_free_item)->next;

    /* I totally disconnect the element from the connected list */
    old_head->next = NULL;
    
    return &((sm->kernel_stack)[index]);        
}

/**
 * insert_free_item - Insert an element of free stack at the top of the connected list of free stack elements.
 *
 * @item: Puntor at the stack element to be included in the connected list
 * @sm: Safety metadata pointer
 */
void insert_free_item(stack_item *item, security_metadata *sm) {
    
    int index;

    index = ((unsigned long)item - (unsigned long)sm->kernel_stack)/sizeof(stack_item);
    
    if(index < 0) {
        pr_err("%s: [ERROR INSERT FREE ITEM] [%d] Value %d of the index is not valido\n", MOD_NAME, current->pid, index);
        kill_process();
    }

    /* Inserting the new stack element within the connected list */
    (sm->free_items)[index].next = sm->first_free_item;
    sm->first_free_item = &((sm->free_items)[index]);    
}

/**
 * del_item_stack - Remove a stack element from the kernel stack
 *
 * @item: pock to the stack element to be removed from the kernel stack
 * @sm: Safety metadata pointer
 */
void del_item_stack(stack_item *item, security_metadata *sm) {

#ifdef SHOW_STACK_KERNEL
    pr_info("%s: [INVALID OPCODE HOOK][DELETE ITEM STACK][%d] The element in the Kernel Stack that you want to eliminate: (%px, %px)\n",
    MOD_NAME,
    current->pid,
    (void *)item->return_address,
    (void *)item->addr_stack_user);
#endif

    if(sm->base == item) {
        sm->base = item->next;
        if(sm->base != NULL) {
            (sm->base)->prev = NULL;
        } else {
            sm->top = sm->base;    
        }
    } else if(sm->top == item) {
        sm->top = item->prev;
        (sm->top)->next = NULL;
    } else {
        (item->prev)->next = item->next;
        (item->next)->prev = item->prev;
    }

    /* I completely disconnect from the list the element I removed */
    item->next = NULL;
    item->prev = NULL;

    /* Register that the removed stack element can be used to keep new validation information*/
    insert_free_item(item, sm);
}


#ifdef SINGLE_ADDRESS_ONE_COPY_FROM_USER
#ifdef LOG_SYSTEM
int single_address_one_copy(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm, unsigned long regs_ip)
#else
int single_address_one_copy(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm)
#endif
{

    int ret;
    int suc_counter;
    unsigned long ret_addr_user;
    stack_item *victim;
    stack_item * curr_item;
    stack_item *curr_res;
    stack_item *prev_stack_item;
    unsigned long ret_addr_kernel;
    unsigned long user_stack_address_kernel;

    /*
     * I recover the pointer at the current top of the Kernel Stack to cause information on information.
     * The doubly connected list will be marked by the last element towards the first via
     * The pointer to the previous element on the list.It is necessary to start from the top to be able to
     * Use the residual detection mechanism on the Kernel Stack.
     */

    curr_item = top_stack;

    /* Number of Return Address on the user stack that have been modified abnormally                      */
    suc_counter = 0;

    /*
     * If during the scan I find the element in the stack that contains the validation information for the
     * Return Address to be used then this element must be removed from the stack.For the moment not
     * I still know if we are in a type II scenario, and therefore, I take on that there is no victim.
     */

    victim = NULL;


    /*
     * Itero on all couples present in the Kernel Stack looking for that containing the information to validate
     * The return address on the top of the user stack to be used for the current ret.The other return addresses
     * will be validated only in the event of the SUC type event on the address on top of the user stack.In the event of an event
     * SUC, a copy of the User Stack will be generated to be shown on log files via the Daemon KWorker.
     */

    while((void *)curr_item != NULL) {

        /* The current couple contains the information to validate a specific return address on the user stack*/

        /* Recovery the expected value of the return address to be validated in the current couple               */
        ret_addr_kernel = curr_item->return_address;

        /* Recovery the position on the user stack of the return address to be validated in the current couple*/
        user_stack_address_kernel = curr_item->addr_stack_user;

        /*
         * I am interested in validating only the return address on the top of the user stack.I check if
         * The pair of validation information contained by the current stack element are related to the address of
         * Return that must be used by the current Education of Ret.
         */

        if(user_stack_address_kernel != user_stack_address) {

            /* I pass to the previous element in the stack (I move to the base of the stack)        */
            curr_item = curr_item->prev;
            continue;
        }

        /* Recovery the return address that should be used by the current ret   */
        ret = copy_from_user(&ret_addr_user, (void *)user_stack_address_kernel, 8);

        /*Check if the return address to be validated was read completely through the copy_from_user()          */
        if(ret) {
            pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in reading the return address on the top of the user stack@%px\n",
            MOD_NAME,
            current->pid,
            (void *)user_stack_address_kernel);
            return -1;
        }

        /* I register the return address from which the program must eventually continue */
        *return_address = ret_addr_user;

        /* I register the pointer to the element that must be removed from the Kernel Stack being a scenario II */
        victim = curr_item;

        /* I recover the pointer to the previous element to the one I have on Matching*/
        curr_res = curr_item->prev;

        /*
         * The mechanism to identify any residues that are present active
         * in the stack kernel.It is not possible to have other pairs of validation in the
         * Stack Kernel who share the same address in the user stack but that yes
         * They find under the kernel stack.
         */

        while(curr_res != NULL) {

            if(curr_res->addr_stack_user == victim->addr_stack_user) {

                /* Except for the predecessor of the element before disconnecting it from the list */
                prev_stack_item = curr_res->prev;

                /* Removal of the residue from the Kernel Stack */
                del_item_stack(curr_res, sm);

                curr_res = prev_stack_item;

                continue;
            }
            curr_res = curr_res->prev;
        }

#ifdef DEBUG_CHECK_RETURN_ADDRESS
        pr_info("%s: [CHECK ALL RETURN ADDRESS] Return address on the Kernel Stack %px\n", MOD_NAME, (void *)ret_addr_kernel);
        pr_info("%s: [CHECK ALL RETURN ADDRESS] Return address on the user stack %px\n", MOD_NAME, (void *)ret_addr_user);
        pr_info("%s: [CHECK ALL RETURN ADDRESS] User stack position                  %px\n", MOD_NAME, (void *)user_stack_address_kernel);
#endif

        /*
         * I check if the return address on the top of the user stack has been changed abnormally.
         * In this case, we move on to the validation of the other return addresses to look for all the anomalous changes.
         * This information allows you to more easily reconstruct the 'malicious' path performed by the application.
         * Eventually, the 'corrupt user stack' stacks are generated for the current thread.
         */

        if(ret_addr_user != ret_addr_kernel) {

            pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] Error in comparison: expected value %px\tPresent value %px\n",
            MOD_NAME,
            (void *)ret_addr_kernel,
            (void *)ret_addr_user);

            suc_counter++;

#ifdef LOG_SYSTEM
            /* Generates a 'corrupt user stack' type event                            */
            ret = write_suc_event_to_log_buffer(ret_addr_kernel, ret_addr_user, regs_ip, sm);

            if(ret) {
                pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in the recording of the event in the log buffer\n",
                MOD_NAME,
                current->pid);
                return -1;
            }

            /* Since I had an event of the type 'SUC' all the return addresses to obtain more information possibly */
            curr_item = curr_item->prev;

            while(curr_item != NULL) {
        
                ret_addr_kernel = curr_item->return_address;

                user_stack_address_kernel = curr_item->addr_stack_user;

                ret = copy_from_user(&ret_addr_user, (void *)user_stack_address_kernel, 8);

                /* I check if the return address to be validated has been read completely through the copy_from_user ()         */
                if(ret) {
                    pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in reading the return address on the user stack@%px\n",
                    MOD_NAME,
                    current->pid,
                    (void *)user_stack_address_kernel);
                    return -1;
                }

                if(ret_addr_user != ret_addr_kernel) {

                    pr_err("%s: [ERRORE CHECK ALL RETURN ADDRESS] Error in comparison: expected value %px\tPresent value %px\n",
                    MOD_NAME,
                    (void *)ret_addr_kernel,
                    (void *)ret_addr_user);

                    suc_counter++;

                    ret = write_suc_event_to_log_buffer(ret_addr_kernel, ret_addr_user, regs_ip, sm);

                    if(ret) {
                        pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in the recording of the event in the log buffer\n",
                        MOD_NAME,
                        current->pid);
                        return -1;
                    }
                }

                curr_item = curr_item->prev;
            }            
#endif //LOG_SYSTEM

        }
        break;
    }

    /* I check if we are in a type II scenario to possibly remove the element used for validation  */

    if(victim != NULL) {
        del_item_stack(victim, sm);
    }

    return suc_counter;

}
#endif



#if defined(SINGLE_ADDRESS) || defined(MIX_ADDRESS)
#ifdef LOG_SYSTEM
int single_address(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm, unsigned long regs_ip)
#else
int single_address(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm)
#endif
{

    int ret;
    int suc_counter;
    stack_item * curr_item;
    stack_item *victim;
    unsigned long ret_addr_user;
    unsigned long ret_addr_kernel;
    unsigned long user_stack_address_kernel;
    stack_item *curr_res;
    stack_item *prev_stack_item;
#ifdef SINGLE_ADDRESS_TIMER
    unsigned long temp_cycles1_single;
    unsigned long temp_cycles2_single;
#endif
#ifdef TIMER_COMPARE_RET_ADDR
    int count_ret;
#endif


    curr_item = top_stack;

    suc_counter = 0;

    victim = NULL;

#ifdef TIMER_COMPARE_RET_ADDR
    count_ret = 0;
#endif

    /* Itero on all couples present in the Kernel Stack to validate the corresponding Return Address on the user stack */

    while((void *)curr_item != NULL) {

#ifdef TIMER_COMPARE_RET_ADDR
            count_ret++;
#endif

        /*The current couple contains the information to validate a specific return address on the user stack */

        /* Recovery the expected value of the return address to be validated in the current couple               */
        ret_addr_kernel = curr_item->return_address;

        /* Recovery the position on the user stack of the return address to be validated in the current couple  */
        user_stack_address_kernel = curr_item->addr_stack_user;

#ifdef SINGLE_ADDRESS_TIMER
        temp_cycles1_single = rdtsc();
#endif
        /* Recovery the return address that must be validated at the memory address @user_stack_address_kernel   */
        ret = copy_from_user(&ret_addr_user, (void *)user_stack_address_kernel, 8);

#ifdef SINGLE_ADDRESS_TIMER
        temp_cycles2_single = rdtsc();
#endif

        /* Check if the return address to be validated was read completely through the copy_from_user()          */
        if(ret) {
            pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Reading error of the address of returning from the user stack @%px\n",
            MOD_NAME,
            current->pid,
            (void *)user_stack_address_kernel);
            return -1;
        }

#ifdef SINGLE_ADDRESS_TIMER
        total_time_one_byte += temp_cycles2_single - temp_cycles1_single;

        counter_one_byte++;

        if((counter_one_byte % 100) == 0) {
            pr_info("%s: [INVALID OPCODE HOOK] [%d] [Performance] Time required for the execution of the current copy_from_user() on the single address --> %ld\n",
            MOD_NAME,
            current->pid,
            temp_cycles2_single - temp_cycles1_single);

            pr_info("%s: [INVALID OPCODE HOOK] [%d] [Performance] New total time for the transfer of a single address %ld with a number of executions equal to %ld\n",
            MOD_NAME,
            current->pid,
            total_time_one_byte,
            counter_one_byte);
        }
#endif

        /*
         * The current element of the kernel stack that is analyzing contains information that allows
         * Valid the return address on the top of the user stack.To avoid the invocation of a
         * further copy_from_user () I exceed the return address which will have to be used to restore the
         * correct execution to the return to user mode.Also, since a type II scenario has occurred
         * You have to remove the current element from the Kernel Stack which has been used to validate the address of
         * Return to the top of the user stack.
         */
 
        if(user_stack_address_kernel == user_stack_address) {

            /* I register the return address from which the program will have to continue */
            *return_address = ret_addr_user;

            /*
             * Register the pointer to the element which must be removed following the
             * Scan of couples of information that is present on the Stack Kernel.
             */
            victim = curr_item;

            /* I recover the pointer to the previous element to the one I have on Matching */
            curr_res = curr_item->prev;

            /*
             * The mechanism to identify any residues that are present active
             * in the stack kernel.It is not possible to have other pairs of validation in the
             * Stack Kernel who share the same address in the user stack but that yes
             * They find under the kernel stack.
             */

            while(curr_res != NULL) {

                if(curr_res->addr_stack_user == victim->addr_stack_user) {

                    /* Except for the predecessor of the element before disconnecting it from the list*/
                    prev_stack_item = curr_res->prev;

                    /* Removal of the residue from the Kernel Stack */
                    del_item_stack(curr_res, sm);

                    curr_res = prev_stack_item;

                    continue;
                }

                curr_res = curr_res->prev;
            }
        }

#ifdef DEBUG_CHECK_RETURN_ADDRESS
        pr_info("%s: [CHECK ALL RETURN ADDRESS] Return address on the Kernel Stack %px\n", MOD_NAME, (void *)ret_addr_kernel);
        pr_info("%s: [CHECK ALL RETURN ADDRESS] Return address on the user stack %px\n", MOD_NAME, (void *)ret_addr_user);
        pr_info("%s: [CHECK ALL RETURN ADDRESS] User stack position %px\n", MOD_NAME, (void *)user_stack_address_kernel);
#endif

        /*
         * I check if the return address on the user stack has been changed abnormally.In this case, yes
         * It continues with the validation of the other return addresses to look for further anomalous changes.
         * Eventually, the 'corrupt user stack' stacks are generated for the current thread.
         */

        if(ret_addr_user != ret_addr_kernel) {

            pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS]Error in comparison: expected value %px\tPresent value %px\n",
            MOD_NAME,
            (void *)ret_addr_kernel,
            (void *)ret_addr_user);

            suc_counter++;

#ifdef LOG_SYSTEM
            /* Generates a 'corrupt user stack' type event                            */
            ret = write_suc_event_to_log_buffer(ret_addr_kernel, ret_addr_user, regs_ip, sm);

            if(ret) {
                pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in the recording of the event in the log buffer\n",
                MOD_NAME,
                current->pid);
                kill_process();
            }
#endif //LOG_SYSTEM
        }

        /* I pass to the previous element in the stack (I move to the base of the stack)         */
        curr_item = curr_item->prev;
    }

#ifdef TIMER_COMPARE_RET_ADDR
    if(count_ret == 2001) {
        guard = 1;
    } else {
        guard = 0;
    }
#endif

    /* I check if we are in a type II scenario to possibly remove the element used for validation */

    if(victim != NULL) {

        del_item_stack(victim, sm);

#ifdef MIX_ADDRESS
        /* I have to update the statistics since the frame stack of the current function is about to be removed with the ret*/

/*
        printk("[DEBUG MIX ADDRESS] [RET] somma corrente = %ld        numero corrente pendenti = %d         valore stack pointer corrente = %px\n",
                sm->stack_frame_size_sum,
                sm->num_stack_frame_pend,
                (void *)((sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1]));
*/

        /* I have to remove the size of the current pendant stack stack stack stack */
       
        if((sm->num_stack_frame_pend) > 1)
            sm->stack_frame_size_sum -= ((sm->array_stack_pointers)[(sm->num_stack_frame_pend)-2] - (sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1]);
        else
            sm->stack_frame_size_sum -= ((current->mm)->start_stack - (sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1]);

        /* Cancel the end of the current stacks since it will be logically dealut by the user stack */
        (sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1] = 0;

        /*Decrease the number of pendant frame stacks*/
        (sm->num_stack_frame_pend)--;

/*
        printk("[DEBUG MIX ADDRESS] [RET] somma aggiornata = %ld      numero aggiornato pendenti = %d       valore stack pointer aggiornato = %px\n",
                sm->stack_frame_size_sum,
                sm->num_stack_frame_pend,
                (void *)((sm->array_stack_pointers)[(sm->num_stack_frame_pend)]));
*/
#endif
    }

    return suc_counter;
}
#endif


#ifdef BLOCK_ADDRESS
#ifdef LOG_SYSTEM
int block_address(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm, unsigned long regs_ip)
#else
int block_address(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm)
#endif
{
    int ret;
    stack_item * curr_item;
    stack_item *victim;
    unsigned long ret_addr_kernel;
    unsigned long user_stack_address_kernel;
    int suc_counter;
    int first;
    unsigned long size_copy;
    unsigned long user_stack_address_kernel_last;
    unsigned char *buffer;
    unsigned long mapping_base_address;
    unsigned long *curr_pointer;
#ifdef BLOCK_ADDRESS_TIMER
    unsigned long temp_cycles1_block;
    unsigned long temp_cycles2_block;
#endif
#ifdef TIMER_COMPARE_RET_ADDR
    int count_ret;
#endif


#ifdef TIMER_COMPARE_RET_ADDR
    count_ret = 0;
#endif

    curr_item = top_stack;

    suc_counter = 0;

    victim = NULL;

    /* I check if there are return addresses on the user stack that can be validated*/
    if(sm->base != NULL) {

        /* I still have to copy the portion of the user stack containing all the addresses to be validated */
        first = 1;

        /* Itero on all the elements in the new Kernel Stack starting from the top           */
        while(curr_item != NULL) {

#ifdef TIMER_COMPARE_RET_ADDR
            count_ret++;
#endif
            /* Recovery the expected value of the return address to be validated                        */
            ret_addr_kernel = curr_item->return_address;

            /* Recovery the position on the user stack of the return address to be validated        */
            user_stack_address_kernel = curr_item->addr_stack_user;

#ifdef DEBUG_CHECK_RETURN_ADDRESS
            pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] Correct return address on the Kernel Stack = %px\tposition on the user stack saved at the kernel level = %px\n",
            MOD_NAME,
            current->pid,
            (void *)ret_addr_kernel,
            (void *)user_stack_address_kernel);
#endif

            /* I check if you have to copy the Kernel Buffer the portion of the user stack containing all the return addresses to be validated*/

            if(first) {

                mapping_base_address = user_stack_address_kernel;

#ifdef DEBUG_CHECK_RETURN_ADDRESS
                pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] Position on the user stack of the first return address (RET 1) = %px\n",
                MOD_NAME,
                current->pid,
                (void *)mapping_base_address);
#endif
                /* Recovery the position on the user stack of the first return address entered in the Kernel Stack */
                user_stack_address_kernel_last = (sm->base)->addr_stack_user;

#ifdef DEBUG_CHECK_RETURN_ADDRESS
                pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] Position on the user stack of the latest return address RET N = %px\n",
                MOD_NAME,
                current->pid,
                (void *)user_stack_address_kernel_last);

                pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] Range Stack User containing the return addresses[%px , %px]\n",
                MOD_NAME,
                current->pid,
                (void *)user_stack_address_kernel,
                (void *)user_stack_address_kernel_last);
#endif
                /* Calculation the size of the portion of the user stack to be copied containing the return addresses  */
                size_copy = user_stack_address_kernel_last - user_stack_address_kernel + sizeof(unsigned long);

                /* Alloco the Kernel level Buffer which will contain the portion of the user stack with the Indrizzi */
                buffer = (unsigned char *)kmalloc(size_copy, GFP_KERNEL);

                if((void *)buffer == NULL) {
                    pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] It is not possible to allocate the buffer in which to copy the portion of the user stack\n",
                    MOD_NAME,
                    current->pid);
                    return -1;
                }

#ifdef DEBUG_CHECK_RETURN_ADDRESS
                pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] The base of the Kernel buffer is equal to %px\n",
                MOD_NAME,
                current->pid,                
                (void *)buffer);
#endif

#ifdef BLOCK_ADDRESS_TIMER
                temp_cycles1_block = rdtsc();
#endif
                /* I copy the Kernel Buffer the portion of the user stack containing the return addresses to be validated*/
                ret = copy_from_user((void *)buffer, (void *)user_stack_address_kernel, size_copy);

#ifdef BLOCK_ADDRESS_TIMER
                temp_cycles2_block = rdtsc();
#endif
                if(ret) {
                    pr_err("%s: [ERRORE CHECK ALL RETURN ADDRESS] [%d] Errore nella lettura della porzione di stack utente\n",
                    MOD_NAME,
                    current->pid);
                    return -1;
                }

#ifdef BLOCK_ADDRESS_TIMER
#ifdef CHECK_BUFFER_SIZE
                if(size_copy == BUFFER_SIZE) {
#endif //CHECK_BUFFER_SIZE
                    total_time_block += temp_cycles2_block - temp_cycles1_block;
                    counter_block++;

#ifdef DEBUG_PERFORMANCE_WEAK
                    if((counter_block % 50) == 0) {
#endif //DEBUG_PERFORMANCE_WEAK
                        pr_info("%s: [INVALID OPCODE HOOK] [%d] [Performance]Time required for the transfer of%ld byte --> %ld\n",
                        MOD_NAME,
                        current->pid,
                        size_copy,
                        temp_cycles2_block - temp_cycles1_block);

                        pr_info("%s: [INVALID OPCODE HOOK] [%d] [Performance] New total time for the transfer of a single address %ld with a number of executions equal to %ld\n",
                        MOD_NAME,
                        current->pid,
                        total_time_block,
                        counter_block);
#ifdef DEBUG_PERFORMANCE_WEAK                    
                    }
#endif //DEBUG_PERFORMANCE_WEAK

#ifdef CHECK_BUFFER_SIZE
                }
#endif //CHECK_BUFFER_SIZE

#endif  //BLOCK_ADDRESS_TIMER

#ifdef DEBUG_CHECK_RETURN_ADDRESS
                pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] On the ends of this memory area I have the addresses %px and %px\n",
                MOD_NAME,
                current->pid,
                (void *)((unsigned long *)buffer)[0],
                (void *)((unsigned long *)(buffer + size_copy - 8))[0]);
#endif //DEBUG_CHECK_RETURN_ADDRESS

                /* The Kernel buffer was allocated and populated with the portion of the user stack correctly */
                first = 0;
            }

#ifdef DEBUG_CHECK_RETURN_ADDRESS
            pr_info("%s: [CHECK ALL RETURN ADDRESS] [%d] user_stack_address_kernel = %px\tmapping_base_address = %px\tuser_stack_address_kernel - mapping_base_address = %px\n",
            MOD_NAME,
            current->pid,
            (void *)user_stack_address_kernel,
            (void *)mapping_base_address,
            (void *)(user_stack_address_kernel - mapping_base_address));
#endif //DEBUG_CHECK_RETURN_ADDRESS

            /* Recovery the corresponding return address on the user stack which must be validated */
            curr_pointer = (unsigned long *)(buffer + (user_stack_address_kernel - mapping_base_address));

            /* Comparison the expected return address with the actual return address */
            if((void *)((curr_pointer)[0]) != (void *)ret_addr_kernel) {

                pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Expected @%px %px\tPresent value @%px %px\n",
                MOD_NAME,
                current->pid,
                (void *)&(curr_item->addr_stack_user),
                (void *)ret_addr_kernel,
                (void *)curr_pointer,
                (void *)((curr_pointer)[0]));

                suc_counter++;

#ifdef LOG_SYSTEM
                /* Generates a 'corrupt user stack' type event                                                     */
                ret = write_suc_event_to_log_buffer(ret_addr_kernel, (curr_pointer)[0], regs_ip, sm);
                if(ret) {
                    pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in the recording of the event in the log buffer\n",
                    MOD_NAME,
                    current->pid);
                    kill_process();
                }
#endif

            }

            /*
             * I keep track of the address to which control must be returned to the user level e
             * of the element to be removed from the kernel stack being in a type II scenario
             */

            if(user_stack_address_kernel == user_stack_address) {

                *return_address = (curr_pointer)[0];

                victim = curr_item;
            }

            /* Step to the previous element in the Kernel Stack*/
            curr_item = curr_item->prev;
        }

        if(buffer != NULL)  kfree(buffer);
    }

#ifdef TIMER_COMPARE_RET_ADDR
    if(count_ret == 2001) {
        guard = 1;
    } else {
        guard = 0;
    }
#endif

    /* I check if we are in a type II scenario to possibly remove the element used for validation */

    if(victim != NULL) {
        del_item_stack(victim, sm);
    }

    return suc_counter;
}
#endif


#ifdef MIX_ADDRESS
#ifdef LOG_SYSTEM
int iter_block_address(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm, unsigned long regs_ip)
#else
int iter_block_address(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm)
#endif
{

    int ret;
    stack_item * curr_item;
    stack_item *victim;
    unsigned long ret_addr_kernel;
    unsigned long user_stack_address_kernel;
    int suc_counter;
    unsigned long size_copy;
    unsigned long end;
    unsigned long start;
    unsigned long *curr_pointer;


    curr_item = top_stack;

    suc_counter = 0;

    victim = NULL;

    /*
     * It starts with validating the return address on the top of the Stack Kernel.
     * This address is the most recent and is lower than the others in the user stack
     * Since the user stack grows for decreasing addresses.At each iteration they come
     * identified the details of the portion of the user stack to be copied.To each iteration
     * The 'Curr_item' variable aims at the stack element containing the validation information
     * relating to the return address on the most recent user stack that has not yet been validated.
     */

    while(curr_item != NULL) {
        
        /* I have to calculate the extremes of the portion of the user stack to be copied for this iteration */
        start = curr_item->addr_stack_user;

        size_copy = 0;

        /* Check if I go out of the user stack of the current thread */

        if((start + N) > (current->mm)->start_stack) {
            size_copy = (current->mm)->start_stack - start;
        } else {
            size_copy = N;
        }

        end = start + size_copy;

        /* I copy the portion of the user stack that has been identified */
        ret = copy_from_user((void *)sm->copy_stack_user, (void *)start, size_copy);

        if(ret) {
            pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in reading the portion of Stack during the iteration\n",
            MOD_NAME,
            current->pid);
            return -1;
         }

        /* 
         * Inside this portion of Stack there is at least the return address associated with the element
         * of current stack.I pass to validate all the return addresses that are present within
         * This portion of stack.This procedure is right since I am crossing the elements of the
         * Stack Kernel from the top to the base and the value of the address in which they are in the user stack
         * It grows.
         */

        while((curr_item != NULL) && ((curr_item->addr_stack_user + 8) < end)) {

            /* Recovery the correct and confident return address that should be present on the user stack */
            ret_addr_kernel = curr_item->return_address;

            /* Recovery of his position on the user stack */
            user_stack_address_kernel = curr_item->addr_stack_user;

            /* Recovery the corresponding actual return address on the user stack to be validated */
            curr_pointer = (unsigned long *)(sm->copy_stack_user + (user_stack_address_kernel - start));

            /* Comparison the expected return address with the actual return address*/
            if((void *)((curr_pointer)[0]) != (void *)ret_addr_kernel) {

                pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Expected @%px %px\tPresent value @%px %px\n",
                MOD_NAME,
                current->pid,
                (void *)&(curr_item->addr_stack_user),
                (void *)ret_addr_kernel,
                (void *)curr_pointer,
                (void *)((curr_pointer)[0]));

                suc_counter++;

#ifdef LOG_SYSTEM
                /* Generates a 'corrupt user stack' type event                                                     */
                ret = write_suc_event_to_log_buffer(ret_addr_kernel, (curr_pointer)[0], regs_ip, sm);
                if(ret) {
                    pr_err("%s: [ERROR CHECK ALL RETURN ADDRESS] [%d] Error in the recording of the event in the log buffer\n",
                    MOD_NAME,
                    current->pid);
                    return -1;
                }
#endif

            }

            /*
             * I keep track of the address to which control must be returned to the user level e
             * of the element to be removed from the kernel stack being in a type II scenario
             */

            if(user_stack_address_kernel == user_stack_address) {

                *return_address = (curr_pointer)[0];

                victim = curr_item;
            }

            /* Step to the previous element in the Kernel Stack */
            curr_item = curr_item->prev;

        }
        
    }

    if(victim != NULL) {

        del_item_stack(victim, sm);

/*
        printk("[DEBUG MIX ADDRESS] [RET] somma corrente = %ld        numero corrente pendenti = %d         valore stack pointer corrente = %px\n",
                sm->stack_frame_size_sum,
                sm->num_stack_frame_pend,
                (void *)((sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1]));
*/

        /* I have to update the statistics since the frame stack of the current function is about to be removed with the ret*/

        /* I have to remove the size of the current pendant stack stack stack stack */
        if((sm->num_stack_frame_pend) > 1)
            sm->stack_frame_size_sum -= ((sm->array_stack_pointers)[(sm->num_stack_frame_pend)-2] - (sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1]);
        else
            sm->stack_frame_size_sum -= ((current->mm)->start_stack - (sm->array_stack_pointers)[(sm->num_stack_frame_pend)-1]);

        /* Cancel the end of the current stacks since it will be logically dealut by the user stack*/
        sm->array_stack_pointers[(sm->num_stack_frame_pend)-1] = 0;

        /* Decrease the number of pendant frame stacks */
        (sm->num_stack_frame_pend)--;

/*
        printk("[DEBUG MIX ADDRESS] [RET] somma aggiornata = %ld      numero corrente aggiornata = %d       valore stack pointer aggiornato = %px\n",
                sm->stack_frame_size_sum,
                sm->num_stack_frame_pend,
                (void *)((sm->array_stack_pointers)[(sm->num_stack_frame_pend)]));
*/
    }

    return suc_counter;
}
#endif


/**
 * Check_All_Return_Adress - Validation of the return addresses on the user stack that you have
 * The validation information saved in the new Kernel level stack.
 *
 * @top_stack: Puntor at the element at the top of the Kernel Stack (the tail of the list)
 * @user_stack_address: the value of the current stointer user
 * @return_address: pointer to the memory area in which to write the Return Address to be used for the RET current (if it exists)
 * @sm: Safety metadata pointer
 * @regs_ip: the 0x06 byte address that asked the Linux kernel the simulation of the ret
 *
 * @return: returns the value 0 if the return addresses on the user stack have been validated with
 * success;returns the number of SUC events if there is at least one return address that has been modified in
 * abnormal way;Otherwise, in case of error it returns the value -1.
 */
#ifdef LOG_SYSTEM
int check_all_return_adress(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm, unsigned long regs_ip) {
#else
int check_all_return_adress(stack_item* top_stack, unsigned long user_stack_address, unsigned long *return_address, security_metadata *sm) {
#endif

    int suc_counter;


#ifdef SINGLE_ADDRESS_ONE_COPY_FROM_USER
#ifdef LOG_SYSTEM
    suc_counter = single_address_one_copy(top_stack, user_stack_address, return_address, sm, regs_ip);
#else
    suc_counter = single_address_one_copy(top_stack, user_stack_address, return_address, sm);
#endif
#endif

#ifdef SINGLE_ADDRESS
#ifdef LOG_SYSTEM
    suc_counter = single_address(top_stack, user_stack_address, return_address, sm, regs_ip);
#else
    suc_counter = single_address(top_stack, user_stack_address, return_address, sm);
#endif
#endif

#ifdef BLOCK_ADDRESS
#ifdef LOG_SYSTEM
    suc_counter = block_address(top_stack, user_stack_address, return_address, sm, regs_ip);
#else
    suc_counter = block_address(top_stack, user_stack_address, return_address, sm);
#endif
#endif

#ifdef MIX_ADDRESS
    /*
     * If the stack is made up of a single element then it makes no sense to copy portions of the user stack.
     * If there are at least two return addresses that can be validated, check if the average size
     * of the active frame stacks is less than the S. threshold in this case, the garbage byte are not a problem
     * and it can be preceded with the iterative copy of portions of the user stack;otherwise, the number of bytes
     * garbage is too large and the mapping 1-to-1 approach of the return addresses and the
     * Copy_from_user ().
     */

    if((sm->base == sm->top) || ((((sm->stack_frame_size_sum)) / (sm->num_stack_frame_pend)) > S)) {

#ifdef LOG_SYSTEM
        suc_counter = single_address(top_stack, user_stack_address, return_address, sm, regs_ip);
#else
        suc_counter = single_address(top_stack, user_stack_address, return_address, sm);
#endif
    
    } else {

#ifdef LOG_SYSTEM
        suc_counter = iter_block_address(top_stack, user_stack_address, return_address, sm, regs_ip);
#else
        suc_counter = iter_block_address(top_stack, user_stack_address, return_address, sm);
#endif

    }
#endif

    return suc_counter;
}



