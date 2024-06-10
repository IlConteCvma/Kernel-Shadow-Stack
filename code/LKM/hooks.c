#include "includes/driver-core.h"
#include "includes/hooks.h"
#include "includes/kss_struct.h"
#include "includes/kss_hashtable.h"
#include "includes/utils.h"
#include "includes/logging.h"


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

/*
 * Kernel Probe to obtain the address of the Kallsyms_lookup_Name () function.
 * This function allows you to recover the addresses of events managers
 * of interest in order to check if the current version of the kernel can
 * be used.
 */
struct kprobe kp_kallsyms_lookup_name = {
    .symbol_name = kallsyms_lookup_name_func
};
#endif

struct kprobe kp_kernel_clone = {
    .symbol_name = kernel_clone_func,
    .pre_handler = handler_kernel_clone
};

/*
 * Kernel Probe to intercept the allocation of safety metadata.When
 * new threads will be generated, it occurs if there is a need to allocate
 * The safety metadata before the request for
 * simulate calls and ret.
 */
struct kprobe kp_finish_task_switch = {
    .symbol_name = finish_task_switch_func,
    .pre_handler = handler_finish_task_switch
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
struct kprobe kp_finish_task_switch_cold = {
    .symbol_name = finish_task_switch_cold_func,
    .pre_handler = handler_finish_task_switch
};
#endif

/*
 * Kernel Probe to intercept the execution of the Do_exit () function.In the
 * DO_EXIT () function will be released allocated safety metadata.
 */
struct kprobe kp_do_exit = {
    .symbol_name = do_exit_func,
    .pre_handler = hook_do_exit
};


/**
 * install_kprobes - KPROBES installation necessary to correctly use security architecture.
 * The hook on the do_exit () allows you to dealocate the data structures used in architecture while the hooks on the
 * Finish_task_Switch () allow you to allocar them and initialize them.The hook on the kernel_clone () allows you to use
 * correctly the reference counter in order to dealut the data structures shared by the threads of the same
 * process and to be dismantled the kernel module correctly.
 *
 * @return: return 1 if all the kProbe have been successfully allocated;Otherwise, it returns the value 0.
 */
int install_kprobes(void) {
    int ret;


    /* Install the proe kernels on the finish_task_switch() */
    ret = register_kprobe(&kp_finish_task_switch);

    if(ret < 0) {
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE #1 on 'finish_task_switch()'\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

     #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    ret = register_kprobe(&kp_finish_task_switch_cold);

    if(ret < 0) {
        unregister_kprobe(&kp_finish_task_switch);
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE #2 on 'finish_task_switch()' %d \n",
        MOD_NAME,
        current->pid,
        ret);
        return 0;
    }
    #endif

    /* Install the KPROBE on the do_exit()                 */
    ret = register_kprobe(&kp_do_exit);

    if(ret < 0) {
        unregister_kprobe(&kp_finish_task_switch);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        unregister_kprobe(&kp_finish_task_switch_cold);
        #endif
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE on the 'do_exit()'\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

    dprint_info_test("%s: [MODULE INFO TEST] [%d] Do exit register pointer %lx\n",
            MOD_NAME,
            current->pid,
            (unsigned long) &kp_do_exit);

    /* Install the KPROBE on the kernel_clone()                 */
    ret = register_kprobe(&kp_kernel_clone);

    if(ret < 0) {
        unregister_kprobe(&kp_finish_task_switch);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        unregister_kprobe(&kp_finish_task_switch_cold);
        #endif
        unregister_kprobe(&kp_do_exit);
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE on the 'kernel_clone()'\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

    pr_info("%s: [MODULE INIT] [INSTALLATION KPROBE] [%d] Recording of the hooks successfully taken place\n",
    MOD_NAME,
    current->pid);

    return 1;
}

void remove_probes(void){
    unregister_kprobe(&kp_kernel_clone);
    unregister_kprobe(&kp_finish_task_switch);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    unregister_kprobe(&kp_finish_task_switch_cold);
    #endif

    dprint_info_test("%s: [MODULE INFO TEST] [%d] Do exit UNregister pointer %lx\n",
    MOD_NAME,
    current->pid,
    (unsigned long) &kp_do_exit);

    unregister_kprobe(&kp_do_exit);

    pr_info("%s: [MODULE EXIT] [%d] The prob kernels were successfully removed\n",
    MOD_NAME,
    current->pid);

}

/**
 * Handler_finish_task_Switch - allows you to allocate the data structures per -keep if the current thread
 * Use our security architecture.The Finish_Task_Switch () function is invoked by the function
 * Context_Switch ().If the thread is part of our architecture and the safety metadata have not been
 * still allocated then its allocation is performed.
 */
int handler_finish_task_switch(struct kprobe *pk, struct pt_regs *regs) {

    int i;
    char *absolute_path;
    char buf[MAX_PATH_EXEC] = {0};
    security_metadata *sm;
    unsigned long *end_of_stack;


    int found;
    ht_item *data;


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

            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Allocation and initialization of security metadata...\n", MOD_NAME, current->pid);
            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Initial value end_of_stack[0] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[0]);
            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Initial value end_of_stack[1] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[1]);
            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Initial value end_of_stack[2] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[2]);

            /* Set the Magic Number to carry out checks on the state of the original Stack Kernel              */
            end_of_stack[0] = (unsigned long)MAGIC_NUMBER;
            end_of_stack[2] = (unsigned long)MAGIC_NUMBER;

            /* Alloc the memory for the data structure containing the security metadata                              */
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
             * 
             */
            /* Indicates whether the element corresponding to the current thread inside the hash table was found */
            found = 0;

            /* Iter on the elements that fall into the bucket associated with the address of the MM structure of the current thread */

            hash_for_each_possible(ht_kss, data, ht_list_next, (unsigned long)current->mm) {
            
                /* I check if the current element is associated with the current thread mm.If positive, the current thread is not the main thread. */
                if((unsigned long)data->mm_address == (unsigned long)current->mm) {

                    /* The Reference Counter has already been icnmented by the creator thread*/
                    /** Recovery the reference to the instrument map.If the Instrum_MAP command is worth Null, not
                     * has still been performed.Consequently, the communication of the map by the map must be awaited
                     * Loader Elf via the IOCTL ().
                     */

                    if((void *)data->instrum_map_address != NULL) {
                        dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Indirizzo mappa di instrumentazione = %px\tReference Counter = %d\n",
                                MOD_NAME,
                                current->pid,
                                (void *)data->instrum_map_address,
                                data->reference_counter);
                        /* I recover the pointer to the instrument map shared among the threads belonging to the same process */
                        sm->instrum_map = (struct ioctl_data *)data->instrum_map_address;
                    }
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

            if(!found) {
                dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Il Loader ELF non ha ancora comunicato la mappa di instrumentazione...\n", MOD_NAME, current->pid);
            }

            /* Set the pointer to the data structure containing the security metadata             */
            end_of_stack[1] = (unsigned long)sm;
            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Final value end_of_stack[0] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[0]);
            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Final value end_of_stack[1] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[1]);
            dprint_info_hook("%s: [KPROBE finish_task_switch()] [%d] Final value end_of_stack[2] --> %px\n", MOD_NAME, current->pid, (void *)end_of_stack[2]);

        }        
    }
  
    return 0;
}

/**
 * hook_do_exit -Allows you to dealocate the per-thread data structures in the event that the executable
 * Use our security architecture and any information shared among the threads
 * that belong to the same process.
 */
int hook_do_exit(struct kprobe *p, struct pt_regs *regs) {

    unsigned long *end_of_stack;
    security_metadata *sm;
    int new_reference_counter;
    ht_item *data;
#ifdef LOG_SYSTEM
    param_kworker *pk;
    size_t size;
#endif

    /* Recovery the base of the original kernel stack for the current thread     */
    GET_KERNEL_STACK_BASE(end_of_stack);

    /* I check if the current thread is part of our security architecture to dealut resources */

    if(check_integrity_security_metadata(end_of_stack)) {
        dprint_info_hook("%s: [KPROBE do_exit()] [%d] MATCHING Application name --> A thread is ending "
               "della mia architettura\n", MOD_NAME, current->pid);

        dprint_info_hook("%s: [KPROBE do_exit()] [%d] The state of the Kernel Stack is compatible with respect to safety architecture. "
               "The deallocation was successfully performed\n", MOD_NAME, current->pid);
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
         /*
         * It is possible that there is the element within the HT associated with the process to which the
         * current thread belongs.If the instrument map has finished with an error
         * Then this element has already been removed (if the monitoring system is also active)
         * or has never been inserted.
         */

        hash_for_each_possible(ht_kss, data, ht_list_next, (unsigned long)current->mm) {

            /* I check if the current element is the one associated with the current process*/
            if((unsigned long)data->mm_address == (unsigned long)current->mm) {
                if((unsigned long)data->instrum_map_address != (unsigned long)sm->instrum_map) {
                    pr_err("%s: [ERRORE KPROBE do_exit()] [%d] Le mappe di instrumentazione non coincidono: %px\t%px\n",
                    MOD_NAME,
                    current->pid,
                    (void *)data->instrum_map_address,
                    (void *)sm->instrum_map);
                    break;
                }
                /*Atomically decrease the reference counter since the current thread is ending the execution */
                new_reference_counter = __sync_sub_and_fetch(&(data->reference_counter), 1);
                dprint_info_hook("%s: [KPROBE do_exit()] [%d] New value of the Reference Counter = %d\n",
                    MOD_NAME,
                    current->pid,
                    new_reference_counter);
                /* I check if the current thread is the last to have the reference to this shared information*/
                if(new_reference_counter == 0) {

                    /* I disconnect the element from the hash table */
                    hash_del(&(data->ht_list_next));
                    /* deallocoTheInstrumentMap */
                    if(data->instrum_map_address)   kfree((void *)data->instrum_map_address);
                    dprint_info_hook("%s: [KPROBE do_exit()] [%d] The instrument map was successfully deallocated\n", MOD_NAME, current->pid);
        #ifdef LOG_SYSTEM
                    /* deallocoMonitoringInformation */
                    if(data->lsi->program_name)     kfree((void *)data->lsi->program_name);
                    if(data->lsi)                   kfree((void *)data->lsi);

                    dprint_info_hook("%s: [KPROBE do_exit()] [%d] The monitoring information has been successfully deallocated\n", MOD_NAME, current->pid);
        #endif
                /* Dealloco the element I discussed from HT */
                    kfree((void *)data);
                }
                break;
            }
        }

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
int handler_kernel_clone(struct kprobe *p, struct pt_regs *regs) {

    char *absolute_path;
    char buf[MAX_PATH_EXEC] = {0};
    ht_item *data;

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

        /* Recovery the reference to the element in the HT associated with the process to which the current thread belongs */
        hash_for_each_possible(ht_kss, data, ht_list_next, (unsigned long)current->mm) {

            if((unsigned long)(data->mm_address) == (unsigned long)current->mm) {

                    /*Atomically increase the reference counter associated with this element of the hash table */
                    __sync_add_and_fetch(&(data->reference_counter), 1);
            }
        }

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
kallsyms_lookup_name_t get_kallsyms_lookup_name(void) {

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

/**
 * My_invalid_op_handler - It is the new high -level C manager for Invalid Optures.In the moment
 * In which this event occurs, a check is made to see if it is wanted or not.If it's
 * has been intentionally generated by our Elf Loader then the relative logic will be performed
 * to our security architecture;Otherwise, the control will be passed to the default manager
 * of the Linux kernel for this type of event.
 *
 * @regs: Puntor to the PT_REGS data structure
 */
void my_invalid_op_handler(struct pt_regs *regs) {

    int ret;
    char buf[256] = {0};
    char *absolute_path;
    unsigned long ret_addr_user;
    unsigned long *end_of_stack;
    security_metadata *sm;

    unsigned long ret_instr_addr;

#ifdef SINGLE_ADDRESS_TIMER
    unsigned long temp_cycles1;
    unsigned long temp_cycles2;
#endif
#ifdef TIMER_COMPARE_RET_ADDR
    unsigned long temp_cycles1_compare;
    unsigned long temp_cycles2_compare;
#endif

    /* Base of the original kernel level stack of the current thread           */
    end_of_stack = NULL;

    /* Recovery the name of the executable of which the current process is an application     */
    absolute_path = get_absolute_pathname(buf);

    if(IS_ERR(absolute_path) || strlen(absolute_path) != strlen(absolute_path_elf_loader) || strcmp(absolute_path_elf_loader, absolute_path)) {

        pr_info("%s: [ERROR INVALID OPCODE HOOK] [%d] It is not the Loader Elf --> I perform the default manager of Invalid Opcode...\n",
        MOD_NAME,
        current->pid);

        exc_invalid_op(regs);

    } else {

        dprint_info_hook("%s: [INVALID OPCODE HOOK] [%d] The Loader Elf is running... Address of the Ret instruction to be simulated= %px\n",
            MOD_NAME,
            current->pid,
            (void *)regs->ip);

            /*
         * I recover the pointer at the base of the original Kernel Stack Stack of the current thread.
         * On the base the pointer is stored to metadata relating to our security architecture
         * including the base and top of the new Kernel level Stack containing the information of
         * Validation of return addresses.
         */

        GET_KERNEL_STACK_BASE(end_of_stack);

        /* I check the integrity of the safety metadata and the original kernel level stack */
        if(!(check_integrity_security_metadata(end_of_stack))) {
            pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] The original kernel level stack or safety metadata are not in the expected state\n",
            MOD_NAME,
            current->pid);
            kill_process();
        }

        /* Recovery the pointer to security metadata */
        GET_SECURITY_METADATA(end_of_stack, sm);

        /* Recovery the position of the 0x06 byte which requested the simulation of the ret */ 
        ret_instr_addr = (unsigned long)regs->ip;

        /*
         * Control if the 0x06 byte that asked for the simulation of the Ret was actually inserted by the
         * Loader Elf.From the original security metadata recovery the pointer to the instrument map
         * for the current process.If the 0x06 byte address is not present in the instrument map
         * relating to the ret then the process must be finished since the simulation request of the
         * Ret was not made by the Loader Elf.
         */

        ret = check_0x06(ret_instr_addr, sm);

        if(!ret) {
            pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d]The simulation of a RET with a 0x06 byte was required @%px Not inserted by the Loader Elf\n",
            MOD_NAME,
            current->pid,
            (void *)regs->ip);
            kill_process();
        }

        /*
         * At this point, I have the correct information between the safety metadata to simulate the ret
         * Current and the simulation of the current Ret was actually requested by the Elf Loader.Must
         * validate the return addresses that are present on the user stack and that have the correspondents
         * Validation information on the new Kernel Stack.Possibly, if the monitoring system is
         * Active, events will be generated in the current thread log buffer.
         */

        /*
         * I check the status of the new Kernel stack implemented as a double -connected list.If the stack
         * Kernel is empty then we are necessarily in a ni type scenario since the return address
         * present on the top of the user stack cannot be validated.Otherwise, Matching must be searched for
         * Itendo on all validation information that is present in the Kernel Stack as it is possible
         * who previously had the type in type scenarios that left residues on the stack.Self
         * At the end of the iteration, no match was found then we are in the presence of a scenario ni.
         */
      
        if((void *)sm->base == NULL) {

            /*
             * This misalignment between the two stacks does not necessarily indicate the presence of an ongoing attack.
             * In fact, it is possible that the Return to be simulated is associated with an unstroced call.For example,
             * There are functions of external bookstores that invoke the functions present in the executable loaded by
             * Loader Elf (E.G., the Libc main that invokes the main loaded main) or return to
             * Perform code in a memory area created in Run-time.To increase safety in this
             * Scenario, it is possible to verify whether the instruction prior to that episode by the Return Address present
             * On the top of the user stack it is actually a call education.
             */

    #ifdef SINGLE_ADDRESS_TIMER
            temp_cycles1 = rdtsc();
    #endif

    /* Recovery the return address to use which is present on the top of the user stack             */
            ret = copy_from_user(&ret_addr_user, (unsigned char *)regs->sp, 8);

    #ifdef SINGLE_ADDRESS_TIMER
            temp_cycles2 = rdtsc();
    #endif

        /*I check if the return address on the top of the user stack has been read completely */
            if(ret) {
                pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] [0] Error in the recovery of the Return Address from the top of the user stack %px [byte Unread--> %d]\n",
                MOD_NAME,
                current->pid,
                (void *)regs->sp,
                ret);
                kill_process();
            }

            dprint_info_hook("%s: [INVALID OPCODE HOOK] [%d] The Kernel level Stack is empty and it is not possible to validate any return address to the user stack\n",
                MOD_NAME,
                current->pid);

            dprint_info_hook("%s: [INVALID OPCODE HOOK] [%d] The return address on the top of the user stack is%px\n",
                MOD_NAME,
                current->pid,
                (void *)ret_addr_user);

    #ifdef SINGLE_ADDRESS_TIMER
            /* The time required for the execution of the copy_fromer () on the single address */
            total_time_one_byte += temp_cycles2 - temp_cycles1;

            /* Increase the number of copy_from_user () that were performed on the single address             */
            counter_one_byte++;

            if((counter_one_byte % 100) == 0) {
                pr_info("%s: [INVALID OPCODE HOOK] [%d] [Performance] New total time for the transfer of a single address %ld with a number of executions equal to %ld\n",
                MOD_NAME,
                current->pid,
                total_time_one_byte,
                counter_one_byte);
            }
    #endif
    #ifdef LOG_SYSTEM
            /* Generates a ni type event*/
            ret = write_ret_event_to_log_buffer(regs->ip, ret_addr_user, sm, false);
            if(ret) {
                pr_err("%s: [ERROR INVALID OPCODE] [Empty stack] [%d] Error in the recording of the Ni event in the log buffer\n",
                MOD_NAME,
                current->pid);
                kill_process();
            }
    #endif //LOG_SYSTEM
    /*
             * Since the Kernel Stack does not contain any validation information then I cannot validate
             * No return address on the user stack.However, I can check if education
             * Machine previous to that episode by the Return Address User is a type of call.Indeed,
             * Being returning from a ret, I expect that there is corresponding call education.
             */

            ret = check_call_security((unsigned char *)ret_addr_user);

            if(ret == -1) {
                pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] Error in the recovery of machine education previous to that episode by the Return Address\n",
                MOD_NAME,
                current->pid);
                kill_process();
            }

            /* You can decide both to finish the execution of the process and to make it go on */
            if(ret == 1) {

    #ifdef LOG_SYSTEM
                /* Generates a type event NO CALL */
                ret = write_no_call_event_to_log_buffer(regs->ip, ret_addr_user, sm);
                if(ret) {
                    pr_err("%s: [ERROR INVALID OPCODE] [Empty stack] [%d] Error in the recording of the NO Call event in the log buffer\n",
                    MOD_NAME,
                    current->pid);
                    kill_process();
                }
    #endif

    #ifdef KILL_PROCESS_NO_CALL
                pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] The machine instruction prior to that episode by the Return Address is not oneCALL\n",
                MOD_NAME,
                current->pid);
                kill_process();
    #endif
            }

            dprint_info_hook("%s: [INVALID OPCODE HOOK] [%d]The machine instruction prior to that episode by the Return Address is actually one CALL\n",
                MOD_NAME,
                current->pid);
            
            /* I continue correctly the execution of the program once you return to the user level*/
            regs->ip = ret_addr_user;

            /* I perform the pop operation on the user stack to remove the return address to the top  */
            regs->sp = (unsigned long)((unsigned long *)regs->sp + 1);                        

        } else {

            /*
             * The Stack Kernel contains information that allows you to validate specific return addresses
             * which are present on the user stack.To understand if we are in the presence of a scenario II is necessary
             * Check all the validation information present in the Stack Kernel as it is possible to have
             * had types of type in which they left residues in the stack.
             */

            /*The return address to be used for the simulation of the current education of Return                           */
            ret_addr_user = (unsigned long)0x00;

#ifdef TIMER_COMPARE_RET_ADDR
            temp_cycles1_compare = rdtsc();
#endif

#ifdef LOG_SYSTEM
            ret = check_all_return_adress(sm->top, regs->sp, &ret_addr_user, sm, regs->ip);
#else
            ret = check_all_return_adress(sm->top, regs->sp, &ret_addr_user, sm);
#endif

#ifdef TIMER_COMPARE_RET_ADDR
            temp_cycles2_compare = rdtsc();
#endif

            /* Control if an error has occurred*/
            if(ret == -1) {
                pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] Error during the validation of the return addresses on the user stack\n",
                MOD_NAME,
                current->pid);             
                kill_process();
            }

            #ifdef TIMER_COMPARE_RET_ADDR
            if(guard) {

                /* At the time at the time the time required for the execution of thecopy_from_user() on the single address*/
                total_time_compare += temp_cycles2_compare - temp_cycles1_compare;

                /* Increase the number of copy_from_user() which were performed on the individual address               */
                counter_compare++;

                if((counter_compare % 1000) == 0) {
                    pr_info("%s: [INVALID OPCODE HOOK] [%d] [Performance] New total time for the transfer of a single address %ldwith a number of executions equal to%ld\n",
                    MOD_NAME,
                    current->pid,
                    total_time_compare,
                    counter_compare);
                }
            }
#endif
            /*If there are return addresses that have been changed abnormally then the execution could be stopped*/
            if(ret > 0) {
                pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] Exist %d Return addresses on the User Stack modified anomalously\n",
                MOD_NAME,
                current->pid,
                ret);             
#ifdef KILL_PROCESS
                kill_process();
#endif
            }

            /* I check if I owe the return address to the top of the user stack was recovered during the validation    */
            if(ret_addr_user == (unsigned long)0x00) {

                /*
                 * In the Stack Kernel there is no validation information for the return address
                 * present on the top of the user stack.To continue the execution of the process it is necessary
                 * recover it from the user stack.
                 */

                ret = copy_from_user(&ret_addr_user, (unsigned char *)regs->sp, 8);

                /* I check if the return address on the top of the user stack has been read completely           */
                if(ret) {
                    pr_err("%s: [ERROR INVALID OPCODE HOOK] [%d] [1] Error in the recovery of the Return Address from the top of the user stack [byte Unread --> %d]\n",
                    MOD_NAME,
                    current->pid,
                    ret);
                    kill_process();
                }

#ifdef LOG_SYSTEM
                /* Generates a type eventNI */
                ret = write_ret_event_to_log_buffer(regs->ip, ret_addr_user, sm, false);
                if(ret) {
                    pr_err("%s: [INVALID OPCODE] [Empty stack] [%d] Error in the recording of the type ni event in the log buffer\n",
                    MOD_NAME,
                    current->pid);
                    kill_process();
                }
#endif //LOG_SYSTEM

            } else {
#ifdef LOG_SYSTEM
                /* Generates a type event II */
                ret = write_ret_event_to_log_buffer(regs->ip, ret_addr_user, sm, true);
                if(ret) {
                    pr_err("%s: [INVALID OPCODE] [Empty stack] [%d] Error in the recording of the type II event in the log buffer\n",
                    MOD_NAME,
                    current->pid);
                    kill_process();
                }
#endif //LOG_SYSTEM
            }

            /*
             * At this point, I recovered the return address to be used to continue the execution
             * of the process.The validation of addresses in the user stack was successfully passed or the
             * Kernel form has been compiled to continue the process execution anyway.
             */

    #ifdef DEBUG
            stack_item *curr;
            curr = sm->top;
            pr_info("%s: [INVALID OPCODE HOOK][SHOW STACK KERNEL][%d] --------------------START---------------------- \n", MOD_NAME, current->pid);
            while(curr != NULL) {
                pr_info("%s: [INVALID OPCODE HOOK][SHOW STACK KERNEL][%d] Element in the stack kernel: (%px, %px)\n",
                MOD_NAME,
                current->pid,
                (void *)curr->return_address,
                (void *)curr->addr_stack_user);
                curr = curr->prev;
            }
            pr_info("%s: [INVALID OPCODE HOOK][SHOW STACK KERNEL][%d] --------------------END---------------------- \n\n",
            MOD_NAME,
            current->pid);
    #endif
     /* I continue the execution of the user program correctly */
            regs->ip = ret_addr_user;

            /* EI follow Pop operation on the user stack                  */
            regs->sp = (unsigned long)((unsigned long *)regs->sp + 1);
        }        
    }
}

/**
 * my_spurious_handler - It is the new high -level C manager for the spuries interrupts.In the moment
 * In which a spurious switch occurs, a check is made to see if it is desired or not.Self
 * It was intentionally generated by our Elf Loader then the relative logic will be performed
 * to our security architecture;Otherwise, the control will be passed to the default manager
 * of the Linux kernel for this type of event.
 *
 * @regs: Puntor to the PT_REGS data structure
 */
void my_spurious_handler(struct pt_regs *regs){

    int ret;
    char buf[256] = {0};
    char *absolute_path;
    unsigned long ip_addr;
    unsigned long ret_addr;
    unsigned long *end_of_stack;
    security_metadata *sm;
    stack_item *si;
    
    unsigned long call_instr_addr;

    /*Base of the original kernel level stack of the current thread          */
    end_of_stack = NULL;

    /* Recovery the name of the executable of which the current process is an application  */
    absolute_path = get_absolute_pathname(buf);

    if(IS_ERR(absolute_path) || strlen(absolute_path) != strlen(absolute_path_elf_loader) || strcmp(absolute_path_elf_loader, absolute_path)) {

        pr_info("%s: [MY SPURIOUS HOOK] [%d] It is not the Loader Elf --> I perform the default manager of the Spurous Interrupt\n",
        MOD_NAME,
        current->pid);

        /* Invocation of the manager of the high level of default of the Linux kernel */
        sysvec_spurious_apic_interrupt(regs);

    } else {

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] MATCHING Application name --> Kernel was requested to simulate a call with Int Oxff@%px\n",
            MOD_NAME,
            current->pid,
            (void *)((unsigned char *)regs->ip - 2));

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d]Rip value saved from the firmware is equal to%px\n",
            MOD_NAME,
            current->pid,
            (void *)regs->ip);

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] The address from which the metadata for the call is present is equal to%px\n",
            MOD_NAME,
            current->pid,
            (void *)((unsigned char *)regs->ip + 6));
        
        /* Recovery The pointer at the base of the original Kernel Stack Stack of the current thread */
        GET_KERNEL_STACK_BASE(end_of_stack);

        /*
         * For the simulation of the call it is necessary that the current thread has safety metadata
         * allocated and initialized correctly.I check the status of the original Stack Kernel and dei
         * Safety metadata.
         */

        if(!(check_integrity_security_metadata(end_of_stack))) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d]The original kernel level stack or safety metadata are not in the expected state\n",
            MOD_NAME,
            current->pid);
            kill_process(); 
        }

        /* Recovery the pointer to security metadata */
        GET_SECURITY_METADATA(end_of_stack, sm);

        /* Recovery the position of the Education of Int 0xff that requested the simulation of the call */
        call_instr_addr = (unsigned long)((unsigned char *)regs->ip - 2);  

        /*
         * Control if the Int 0xff education that asked for the simulation of the call was actually
         * Posted by the Loader Elf.Recovery the pointer to the instrument map for the program
         * current.If the address of the INTER 0XFF INSTRUCTION is not present in the instrument map
         * Then the process must be finished since the Loader Elf has not requested this simulation.
         */

        ret = check_int_0xFF(call_instr_addr, sm);

        if(!ret) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d] The simulation of a call with an int 0xff instruction was not legitimate was required\n",
            MOD_NAME,
            current->pid);
            kill_process();
        }

        /* When I arrived here I know that the request is legitimate and the Kernel level stack has been allocated */

        /*
         * Recovery the return address to be placed on user stacks and kernels.This address is
         * has been stored in the new memory region allocated by the Loader Elf.The rescue on the
         * User level stack is necessary since you must simulate exactly a call education.
         * The return address that is saved on the new Kernel level Stack will allow you to carry out
         * A control over the validity of the Return Address.
         */

        ret = copy_from_user(&ret_addr, ((unsigned char *)regs->ip + 14), 8);

        if(ret) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d] Error in the recovery of the Return Address [byte Unread --> %d]\n",
            MOD_NAME,
            current->pid,
            ret);
            kill_process();
        }

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d]The return address that must be saved on the user stack and on the Kernel Stack is%px\n",
            MOD_NAME,
            current->pid,
            (void *)ret_addr);

         /*
         * Recovery the absolute address of the function to which the kernel will have to pass control.This
         * address was stored in the new memory region allocated by the Loader Elf and will be used
         * To update the COCS-> IP so that on the return in user mode it will be divided with the execution
         * from the target function required.
         */

        ret = copy_from_user((void *)&ip_addr, (void *)((unsigned char *)regs->ip + 6), 8);

        if(ret) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d] Error in recovering the address of the function to pass to control[byte Unread --> %d]\n",
            MOD_NAME,
            current->pid,
            ret);
            kill_process();
        }

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] The absolute address of the function to which the kernel will pass the control is%px\n",
            MOD_NAME,
            current->pid,
            (void *)ip_addr);
        
         /* Setto the new value of the Poter's intercitation for when I return to the user level */
        regs->ip = ip_addr;

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] User execution will resume from the address %px\n",
            MOD_NAME,
            current->pid,
            (void *)regs->ip);

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] Before writing the return address, the user staninter has the value %px\n",
            MOD_NAME,
            current->pid,
            (void *)regs->sp);

        /*
         * Since the kernel must simulate a call education, it is necessary to act on the user stack in the following
         * way:
         * 1. I modify the user staninter User downwards making room for a total of 8 bytes.
         * 2. I memorize the return address that will be subsequently used on the top of the user stack.
         */

        /* I modify the user stointer user */
        regs->sp = (unsigned long)((unsigned long *)regs->sp - 1);

        /* The Return Address on the top of the user stack */
        ret = copy_to_user((void *)regs->sp, &ret_addr, 8);

        /* I check if the return address was completely written in the user stack */
        if(ret) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d] Error in writing the Return Address on the user stack[byte unwritten --> %d]\n",
            MOD_NAME,
            current->pid,
            ret);
            kill_process();
        }

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] The new value of the user staninter is equal to %px\n",
            MOD_NAME,
            current->pid,
            (void *)regs->sp);

        dprint_info_hook("%s: [MY SPURIOUS HOOK] [%d] The Return Address written on the User Stack at the address %px it is equal to%px\n",
            MOD_NAME,
            current->pid,
            (void *)regs->sp,
            (void *)ret_addr);
        
         /*
         * At this point, I have to enter the validation information on the top of the new Kernel Stack.The stack
         * Kernel is implemented as a doubtful list of 'stack_item' data structures.The elements
         * that are inserted within this list are the same elements that make up the buffer as
         * Memory 'Kernel_stack' stored among safety metadata.Through the aims it is possible to build
         * A doubly connected list that implements a stack.
         */

        /* Recovery from the List connected a free stack element to position it at the top of the Kernel Stack      */
        si = get_free_item(end_of_stack);

        if((void *)si == NULL) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d] Danger of overflow stack, it is not possible to add an additional return address...\n",
            MOD_NAME,
            current->pid);
            kill_process();
        }

        /*I initial the new stack element by setting the return address and its position in the user stack */
        si->return_address = ret_addr;
        si->addr_stack_user = regs->sp;

        /*
         * I insert the new element in the queue inside the stack kernel checking if the connected list is empty.
         * This corresponds to inserting the element at the top of the Kernel Stack.
         */

        si->next = NULL;

        if(sm->base == NULL) {
            sm->base = si;
            /* In the case of a list with a single element, the head and the coincidon tailo */
            sm->top = sm->base;
            si->prev = NULL;    
        } else {
            si->prev = sm->top;
            (sm->top)->next = si;
            sm->top = si;          
        }

    #ifdef LOG_SYSTEM
        /*Generates a call type event*/
        ret = write_call_event_to_log_buffer(ip_addr, ret_addr, sm);

        if(ret) {
            pr_err("%s: [ERROR MY SPURIOUS HOOK] [%d] Error in the recording of the event in the log buffer\n",
            MOD_NAME,
            current->pid);
            kill_process();
        }
    #endif


    #ifdef MIX_ADDRESS
        /*
         * Update the statistics regarding the average size of the peak stacks of the pending functions.
         * With the execution of a call education it is possible to determine the size of the frame stack for the
         * Function to which the education of Call belongs.
         */

        if(sm->base == sm->top) {

            /*
             * In the case of a single element within the Kernel Stack, they are unable to determine the size.
             * An estimate for Upper Bound is calculated considering the base of the user stack.From this moment, the
             * Calculation of the size of the subsequent nest stacks can be calculated correctly.
             */
            sm->num_stack_frame_pend = 1;
            (sm->array_stack_pointers)[0] = regs->sp;
            sm->stack_frame_size_sum = (current->mm)->start_stack - regs->sp;
        } else {

            (sm->array_stack_pointers)[sm->num_stack_frame_pend] = regs->sp;            
            sm->stack_frame_size_sum += (((sm->array_stack_pointers)[sm->num_stack_frame_pend - 1]) - ((sm->array_stack_pointers)[sm->num_stack_frame_pend]));
            (sm->num_stack_frame_pend)++;
        }
        
    #endif
    #ifdef DEBUG
        stack_item *curr;
        curr = sm->top;
        pr_info("%s: [MY SPURIOUS HOOK][SHOW STACK KERNEL][%d] --------------------START---------------------- \n", MOD_NAME, current->pid);
        while(curr != NULL) {
            pr_info("%s: [MY SPURIOUS HOOK][SHOW STACK KERNEL][%d] Element in the stack kernel: (%px, %px)\n",
            MOD_NAME,
            current->pid,
            (void *)curr->return_address,
            (void *)curr->addr_stack_user);

            curr = curr->prev;
        }
        pr_info("%s: [MY SPURIOUS HOOK][SHOW STACK KERNEL][%d] --------------------END---------------------- \n\n", MOD_NAME, current->pid);
    #endif
    }
}


/**
 * patch_IDT - It performs the binary patch by changing the operand of the education of call target.In this way, the
 * Execution flow is diverted to the new high -level C manager associated with the event.To
 * Restore the original content of the manager, the restoration information is saved inside
 * of the @item data structure.
 *
 * @address_first_Handler: address of the actual (and correct) first level ASM manager of the event @vector_number
 * @address_expected_c_Handler: address of the correct high -level C manager of the event @vector_number
 * @DTR: data structure maintaining information relating to the IDT table
 * @vector_number: numerical identification of the entry target in the IDT table
 * @Handler: address of the new manager C to be installed instead of @address_expected_c_handler
 * @item: data structure containing Binary Patching information
 *
 * @return: returns the value 1 in case of success;Otherwise, it returns the value 0.
 */
int patch_IDT(unsigned long address_first_handler, unsigned long address_expected_C_handler, struct desc_ptr dtr, int vector_number, void *handler, struct info_patch *item) {

    int i;
    int operand;
    unsigned char *byte;
    unsigned long address;
    

    /*
     * I run a byte scan after bytes in search of call instructions in
     * ASM manager of the event.Given a call education, its operando is calculated
     * To determine the address that you will have to jump.We are looking for the call whose
     * target address coincides with @address_expected_c_handler (I.E., the correct
     * high -level C manager).For simplicity, a scan is performed which
     * It involves more than 1024 bytes as these ASM managers are small in size.
     */

    /* Pointer at the beginning of the Asm manager        */
    byte = (unsigned char *)address_first_handler;

    for(i=0; i<1024; i++) {

        /* Check whether the bite i-th represents the operating code of the CALL */

        if(byte[i]==0xE8) {
                
                /* Calculating the operating of the education of CALL   */
                operand = ( (int) byte[i+1]       ) |
                          (((int) byte[i+2]) << 8 ) |
                          (((int) byte[i+3]) << 16) |
                          (((int) byte[i+4]) << 24);
                
                /* Calculation the address of the target function   */
                address = (unsigned long) (((unsigned long)&byte[i+5]) + operand);

                if(address == address_expected_C_handler) {
                    dprint_info_hook("%s: [MODULE INIT] [PATCH IDT] [%d] Matching successfully found for the execution of Binary Patching\n",
                            MOD_NAME,
                            current->pid);
                    item->old_call_operand     = operand;
                    item->new_call_operand     = (int)(((unsigned long)handler)-((unsigned long)(&byte[i+5])));
                    item->call_operand_address = (unsigned int *) &byte[i+1];

                    cr0 = read_cr0();
                    unprotect_memory();

                    /* I modify the operating of current call education on which I have Matching */
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
                    arch_cmpxchg(item->call_operand_address, item->old_call_operand, item->new_call_operand);
        #else
                    cmpxchg(item->call_operand_address, item->old_call_operand, item->new_call_operand);
        #endif

                    /* Except for the current descriptor of the IDT table associated with the requested carrier */
                    memcpy(&(item->old_entry), (void*)(dtr.address + vector_number * sizeof(gate_desc)), sizeof(gate_desc));

	                /* Comparison The new gate so that it can be invoked User side */
                    pack_gate(&(item->my_trap_desc), GATE_INTERRUPT, address_first_handler, 0x3, 0, 0);

                    /* I update the entries of the IDT table  */
                    write_idt_entry((gate_desc*)dtr.address, vector_number, &(item->my_trap_desc));

                    protect_memory();

                    return 1;
                }                            
        }
    }

    return 0;
}