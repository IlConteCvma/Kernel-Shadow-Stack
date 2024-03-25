#include "includes/module-defines.h"
#include "includes/utils.h"
#include "includes/hooks.h"
#include "includes/kss_hashtable.h"
#include "includes/logging.h"

/**
 * Handler_finish_task_Switch - allows you to allocate the data structures per -keep if the current thread
 * Use our security architecture.The Finish_Task_Switch () function is invoked by the function
 * Context_Switch ().If the thread is part of our architecture and the safety metadata have not been
 * still allocated then its allocation is performed.
 */
static int handler_finish_task_switch(struct kprobe *pk, struct pt_regs *regs) {

    int i;
    char *absolute_path;
    char buf[MAX_PATH_EXEC] = {0};
    security_metadata *sm;
    unsigned long *end_of_stack;
#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)
    int found;
    ht_item *data;
#endif


    /* Recovery the absolute path of the program of which the current process is an application */ 
    absolute_path = get_absolute_pathname(buf);

    /* The current thread could have the memory map (mm) equal to Null              */
    if(IS_ERR(absolute_path))   return 0;

    /*
     * I check if the current process is an application for the Elf Loader program.In this case, it is
     * It is necessary to check if safety metadata have already been allocated.In fact, it is
     * It is possible that the following two scenarios occur:
     *
     * 1. The current thread is the main thread of the Loader Elf which has already communicated through
     * IOCTL () to allocate safety metadata.
     * 2. The current thread has already passed for the hook at the Finish_task_Switch () (both main thread and not).
     *
     * In both cases, the safety metadata have already been allocated.The base of the
     * original stack kernel of the current thread to store the pointer to safety metadata.
     */

    if(strlen(absolute_path) == strlen(absolute_path_elf_loader) && !strcmp(absolute_path_elf_loader, absolute_path)) {

        /* Recovery of the base of the original thread original kernel stack */
        GET_KERNEL_STACK_BASE(end_of_stack);

        /*
         *I check if the safety metadata must be allocated taking into account a possible error in the IOCTL ().
         * If the Security_Medadata command is performed before the hook then or the safety metadata were
         * Already allocated (Check_integrity_Security_Medata) or an error has occurred (check_error_security_medata).
         */

        if(!(check_integrity_security_metadata(end_of_stack)) && !check_error_security_metadata(end_of_stack)) {

#ifdef DEBUG_HOOK
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Allocation and initialization of security metadata...\n", MOD_NAME, current->pid);
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Initial value end_of_stack[0] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[0]);
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Initial value end_of_stack[1] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[1]);
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Initial value end_of_stack[2] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[2]);
#endif

            /* Setto the Magic Number to carry out checks on the state of the original Stack Kernel              */
            end_of_stack[0] = (unsigned long)MAGIC_NUMBER;
            end_of_stack[2] = (unsigned long)MAGIC_NUMBER;

            /* Alloco the memory for the data structure containing the security metadata                              */
            sm = (security_metadata *)kzalloc(sizeof(security_metadata), GFP_KERNEL);

            if((void *)sm == NULL) {
                pr_err("%s: [ERROR KPROBE finish_task_switch()] [%d] Error in the allocation of the data structure containing the safety metadata\n",
                MOD_NAME,
                current->pid);
                return 0;
            }

            /* Setto the Magic Number to carry out checks on the status of safety metadata                 */
            sm->magic_number = (unsigned long)MAGIC_NUMBER;

            /* The allocation of the structures given for the implementation of the new Kernel level stack begins...     */

            /* Alloco the memory buffer with which I will build the list of elements of Stack Lberi                    */
            sm->free_items = (free_item *)kmalloc(STACK_SIZE_ARCH * sizeof(free_item), GFP_KERNEL);

            if(sm->free_items == NULL) {
                pr_err("%s: [ERROR KPROBE finish_task_switch()] [%d] Error in the allocation of the buffer for the search for free stack elements\n",
                MOD_NAME,
                current->pid);
                return 0;
            }

            /* Each element on the connected list aims to the logically later element in the memory buffer      */
            for(i=0;i<STACK_SIZE_ARCH - 1;i++) {
                (sm->free_items)[i].next = &((sm->free_items)[i+1]);
            }

            /* Setto the pointer at the head of the list of free stack elements (initially it is empty)         */
            sm->first_free_item = &((sm->free_items)[0]);

            /* Alloco the stack elements that will be included in the connected list that implements the stack         */
            sm->kernel_stack = (stack_item *)kmalloc(STACK_SIZE_ARCH * sizeof(stack_item), GFP_KERNEL);

            if(sm->kernel_stack == NULL) {
                pr_err("%s: [ERROR KPROBE finish_task_switch()] [%d] Error in the allocation of the buffer containing the stack elements\n",
                MOD_NAME,
                current->pid);
                return 0;
            }

            /* Initially the new Kernel Stack does not contain any information: TOP = BASE                        */

            /* The base camp aims at the head of the closely connected list that implements the Kerne Stackl        */
            sm->base = NULL;

            /* The top field points to the queue of the list doubly connected and represents the top of the stack       */
            sm->top = sm->base;

#ifdef MIX_ADDRESS
            /*Initial information to estimate the average size of the frames of the active functions */
            sm->stack_frame_size_sum = 0;
            sm->num_stack_frame_pend = 0;

            sm->array_stack_pointers = (unsigned long *)kzalloc(sizeof(unsigned long) * STACK_SIZE_ARCH, GFP_KERNEL);

            if(sm->array_stack_pointers == NULL) {
                pr_err("%s: [ERROR KPROBE finish_task_switch()] [%d] ARRAY REGISTRATION ERROR CONTAINING THE END OF THE PULCIAL FRAMP STACKS\n",
                MOD_NAME,
                current->pid);
                return 0;   
            }

            sm->copy_stack_user = (unsigned char *)kmalloc(N, GFP_KERNEL);

            if(sm->copy_stack_user == NULL) {
                pr_err("%s: [ERROR KPROBE finish_task_switch()] [%d]Error in the allocation of the buffer to store the copy of the user stack in validation\n",
                MOD_NAME,
                current->pid);
                return 0;   
            }
#endif

#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)
            /*
             * The current thread may have been just created.In this case, it must recover the information
             * shared by the corresponding knot in the hash table.If the instrument map is enabled then it must
             * Recover the pointer on the map.However, if the current thread is the main thread of the process
             * Then the following scenarios could happen:
             * 1. No command of the IOCTL () has yet been performed: there is no element inside the hash table
             * containing the information shared to be recovered.When the Security_Medata command command is invoked
             * We realize that the main data structures have already been allocated and a subset is performed
             * recovering the necessary information from the user.From this moment, the hook on the Finish_task_Switch () will not enter
             * more in this if since the data structures have been allocated.
             * 2. Only the Security_Medata command command was performed: the element inside the hash table has been inserted
             * If you are using the monitoring system.It is possible to recover shared monitoring information but the
             * Map of instrumentation (if you use it) has not yet been recovered by the user.
             * 3. The Security_Medata and IoCTL_instrum_MAP commands were performed: the element inside the hash table is
             * has been inserted and it is possible to recover both the instrument map and monitoring information.
             */
            /* Indicates whether the element corresponding to the current thread inside the hash table was found */
            found = 0;

            /* Iter on the elements that fall into the bucket associated with the address of the MM structure of the current thread */

            hash_for_each_possible(ht_tesi, data, ht_list_next, (unsigned long)current->mm) {
            
                /* I check if the current element is associated with the current thread mm.If positive, the current thread is not the main thread. */
                if((unsigned long)data->mm_address == (unsigned long)current->mm) {

                    /* The Reference Counter has already been icnmented by the creator thread*/

#ifdef IOCTL_INSTRUM_MAP
                    /** Recovery the reference to the instrument map.If the Instrum_MAP command is worth Null, not
                     * has still been performed.Consequently, the communication of the map by the map must be awaited
                     * Loader Elf via the IOCTL ().
                     */

                    if((void *)data->instrum_map_address != NULL) {
#ifdef DEBUG_HOOK
                        pr_info("%s: [KPROBE finish_task_switch()] [%d] Indirizzo mappa di instrumentazione = %px\tReference Counter = %d\n",
                        MOD_NAME,
                        current->pid,
                        (void *)data->instrum_map_address,
                        data->reference_counter);
#endif //DEBUG_HOOK
                        /* I recover the pointer to the instrument map shared among the threads belonging to the same process */
                        sm->instrum_map = (struct ioctl_data *)data->instrum_map_address;
                    }
#endif //IOCTL_INSTRUM_MAP

#ifdef LOG_SYSTEM
                    /*
                     * If the element has been inserted inside the hash table then sure that the monitoring information
                     * were recorded correctly within the hash table since the Security_Medata command was
                     * performed completely (being the thread not descalable in that period).
                     */
                    if((void *)data->lsi == NULL) {
                        pr_err("%s: [KPROBE finish_task_switch()] [%d] La base dovrebbe essere stata già comunicata dal Loader ELF ma non è presente...\n",
                        MOD_NAME,
                        current->pid);
                    }

                    /* Recovery the pointer to monitoring information                                                            */
                    sm->lsi = data->lsi;

                    /* Setto the flag relating to the copy of the portion of the user stack */
                    sm->stack_user_copy = false;

#endif //LOG_SYSTEM
                    found = 1;

                    break;
                }
            }

#ifdef IOCTL_INSTRUM_MAP
#ifdef DEBUG_HOOK            
            if(!found) {
                pr_info("%s: [KPROBE finish_task_switch()] [%d] Il Loader ELF non ha ancora comunicato la mappa di instrumentazione...\n", MOD_NAME, current->pid);
            }
#endif //DEBUG_HOOK
#endif //IOCTL_INSTRUM_MAP
#endif //LOG_SYSTEM || IOCTL_INSTRUM_MAP


            /* Set the pointer to the data structure containing the security metadata             */
            end_of_stack[1] = (unsigned long)sm;

#ifdef DEBUG_HOOK
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Final value end_of_stack[0] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[0]);
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Final value end_of_stack[1] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[1]);
            pr_info("%s: [KPROBE finish_task_switch()] [%d] Final value end_of_stack[2] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[2]);
#endif //DEBUG_HOOK
        }        
    }
  
    return 0;
}

/**
 * hook_do_exit -Allows you to dealocate the per-thread data structures in the event that the executable
 * Use our security architecture and any information shared among the threads
 * that belong to the same process.
 */
static int hook_do_exit(struct kprobe *p, struct pt_regs *regs) {

    unsigned long *end_of_stack;
    security_metadata *sm;
#ifdef LOG_SYSTEM
    param_kworker *pk;
    size_t size;
#endif
#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)
    int new_reference_counter;
    ht_item *data;
#endif


    /* Recovery the base of the original kernel stack for the current thread     */
    GET_KERNEL_STACK_BASE(end_of_stack);

    /* I check if the current thread is part of our security architecture to dealut resources */

    if(check_integrity_security_metadata(end_of_stack)) {

#ifdef DEBUG_HOOK
        pr_info("%s: [KPROBE do_exit()] [%d] MATCHING Application name --> A thread is ending "
               "della mia architettura\n", MOD_NAME, current->pid);

        pr_info("%s: [KPROBE do_exit()] [%d] The state of the Kernel Stack is compatible with respect to safety architecture. "
               "The deallocation was successfully performed\n", MOD_NAME, current->pid);
#endif

        /* Recovery the pointer to security metadata */
        GET_SECURITY_METADATA(end_of_stack, sm);

        /* Dealloco the new kernel stack used by architecture */
        if((void *)sm->free_items != NULL)      kfree((void *)sm->free_items);
        if((void *)sm->kernel_stack != NULL)    kfree((void *)sm->kernel_stack);

#ifdef MIX_ADDRESS
        if(sm->array_stack_pointers != NULL)    kfree((void *)sm->array_stack_pointers);
        if(sm->copy_stack_user != NULL)         kfree((void *)sm->copy_stack_user);
#endif

#ifdef LOG_SYSTEM
        /* I check if you also have to report the events written in the current Buffer of Log */

        if(sm->buffer_log != NULL && sm->offset_log > 0) {

            pk = (param_kworker *)kmalloc(sizeof(struct param_kworker), GFP_KERNEL);

            if(pk == NULL) {
                pr_err("%s: [ERROR KPROBE do_exit()] [%d] Error allocation of the parameters to be passed to Kworker\n",
                MOD_NAME,
                current->pid);
                goto next_step_exit;
            }

            /* It is a buffer of events */
            pk->type = 0;
            pk->user_stack = NULL;
            pk->buffer_log = sm->buffer_log;

            if(sm->lsi == NULL) {

                size = strlen("log_file_");

                pk->program_name = (char *)kmalloc(size + 1, GFP_KERNEL);

                strncpy((pk->program_name), "log_file_", size);

                (pk->program_name)[size] = '\0';

                pk->id_user = 0;
        
            } else {

                size = strlen((sm->lsi)->program_name);

                pk->program_name = (char *)kmalloc(size + 1, GFP_KERNEL);

                strncpy((pk->program_name), (sm->lsi)->program_name, size);

                (pk->program_name)[size] = '\0';

                pk->id_user = (sm->lsi)->id_user;

            }

            pk->tid = current->pid;

            /* I check a new work that must be performed by the Worker Thread */
            __INIT_WORK(&(pk->the_work),(void*)flush_buffer_log,(unsigned long)(&(pk->the_work)));

            queue_work(wq, &(pk->the_work));
        }

next_step_exit:

#endif

#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)

        /*
         * It is possible that there is the element within the HT associated with the process to which the
         * current thread belongs.If the instrument map has finished with an error
         * Then this element has already been removed (if the monitoring system is also active)
         * or has never been inserted.
         */

        hash_for_each_possible(ht_tesi, data, ht_list_next, (unsigned long)current->mm) {

            /* I check if the current element is the one associated with the current process*/
            if((unsigned long)data->mm_address == (unsigned long)current->mm) {

#ifdef IOCTL_INSTRUM_MAP
                if((unsigned long)data->instrum_map_address != (unsigned long)sm->instrum_map) {
                    pr_err("%s: [ERRORE KPROBE do_exit()] [%d] Le mappe di instrumentazione non coincidono: %px\t%px\n",
                    MOD_NAME,
                    current->pid,
                    (void *)data->instrum_map_address,
                    (void *)sm->instrum_map);
                    break;
                }
#endif
                /*Atomically decrease the reference counter since the current thread is ending the execution */
                new_reference_counter = __sync_sub_and_fetch(&(data->reference_counter), 1);

#ifdef DEBUG_HOOK
                pr_info("%s: [KPROBE do_exit()] [%d] New value of the Reference Counter = %d\n",
                MOD_NAME,
                current->pid,
                new_reference_counter);
#endif  //DEBUG_HOOK

                /* I check if the current thread is the last to have the reference to this shared information*/
                if(new_reference_counter == 0) {

                    /* I disconnect the element from the hash table */
                    hash_del(&(data->ht_list_next));

#ifdef IOCTL_INSTRUM_MAP
                    /* deallocoTheInstrumentMap */
                    if(data->instrum_map_address)   kfree((void *)data->instrum_map_address);
#ifdef DEBUG_HOOK
                    pr_info("%s: [KPROBE do_exit()] [%d] The instrument map was successfully deallocated\n", MOD_NAME, current->pid);
#endif  //DEBUG_HOOK
#endif  //IOCTL_INSTRUM_MAP

#ifdef LOG_SYSTEM
                    /* deallocoMonitoringInformation */
                    if(data->lsi->program_name)     kfree((void *)data->lsi->program_name);
                    if(data->lsi)                   kfree((void *)data->lsi);
#ifdef DEBUG_HOOK
                    pr_info("%s: [KPROBE do_exit()] [%d] The monitoring information has been successfully deallocated\n", MOD_NAME, current->pid);
#endif  //DEBUG_HOOK
#endif
                    /* Dealloco the element I discussed from HT */
                    kfree((void *)data);
                }
                break;
            }
        }
#endif //defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)

        kfree((void *)sm);

        /* Atomically decrease the number of threads that are using architecture */
        __sync_sub_and_fetch(&num_threads, 1);
    }

    return 0;
}


/*
 * For a correct management of the reference counter to the elements in the hash table that
 * maintain the information shared by the threads of the same process is appropriate
 * Insert a hook on the kernel_clone () which is performed to generate a new thread
 * of the process.The Reference Counter must be increased by one unit at the moment
 * in which one thread generates another.
 */

/**
 * handler_kernel_clone - Management of the Reference Counter for the element in the hash table
 * associated with the process to which the current thread belongs.When a thread creates it
 * Another then you have to report the presence of a further thread for information
 * Shared.
 */
static int handler_kernel_clone(struct kprobe *p, struct pt_regs *regs) {

    char *absolute_path;
    char buf[MAX_PATH_EXEC] = {0};
#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)
    ht_item *data;
#endif

    /* Recovery the absolute path of the program of which the current process is an application */ 
    absolute_path = get_absolute_pathname(buf);

    /* The current thread could have the memory map (mm) equal to Null               */
    if(IS_ERR(absolute_path))   return 0;

    /* 
     * I check if the current process is an application for the Elf Loader program.In this case, it is
     * It is necessary to increase the reference counter to the element in the hash table to manage it
     * correctly the deallocation.
     */

    if(strlen(absolute_path) == strlen(absolute_path_elf_loader) && !strcmp(absolute_path_elf_loader, absolute_path)) {

        /* I communicate the presence of a new thread that will perform in the architecture */
        __sync_add_and_fetch(&num_threads, 1);

#if defined(IOCTL_INSTRUM_MAP) || defined(LOG_SYSTEM)
        /* Recovery the reference to the element in the HT associated with the process to which the current thread belongs */
        hash_for_each_possible(ht_tesi, data, ht_list_next, (unsigned long)current->mm) {

            if((unsigned long)(data->mm_address) == (unsigned long)current->mm) {

                    /*Atomically increase the reference counter associated with this element of the hash table */
                    __sync_add_and_fetch(&(data->reference_counter), 1);
            }
        }
#endif
       
    } 
    return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
/**
 * get_kallsyms_lookup_name - Recovers the memory address of the Kallsyms_lookup_name () function.
 * This function is invoked if Kallsyms_lookup_Name () is not exported to the current version
 * of the kernel.
 *
 * @return: the memory address of the kallsyms_lookup_name () function in case of success;
 * Otherwise, it returns the Null value.
 */
static kallsyms_lookup_name_t get_kallsyms_lookup_name(void) {

    int ret;
    kallsyms_lookup_name_t kallsyms_lookup_name;

    ret = register_kprobe(&kp_kallsyms_lookup_name);

    if(ret < 0) {
        pr_err("%s [ERROR KALLSYMS_LOOKUP_NAME] [%d] It is not possible to find the address of the functionkallsyms_lookup_name()\n",
        MOD_NAME,
        current->pid);
        return NULL;
    }

    /* Recovery of the address of the Kallsyms_lookup_name () function */
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp_kallsyms_lookup_name.addr;

    unregister_kprobe(&kp_kallsyms_lookup_name);

    return kallsyms_lookup_name;
}
#endif

