#include "include/dirver-core.h"
#include "includes/module-defines.h"
#include "includes/utils.h"
#include "includes/kss_struct.h"
#include "includes/workqueue.h"
#include "includes/hooks.h"
#include "includes/kss_hashtable.h"
#include "includes/logging.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Calavaro");
MODULE_DESCRIPTION("Kernel shadow stack module");
MODULE_VERSION("1.0");


sysvec_spurious_apic_interrupt_t sysvec_spurious_apic_interrupt;    /* Puntatore al gestore C di alto livello di default per la gestione delle interrupt spurie     */
exc_invalid_op_t exc_invalid_op;                                    /* Puntatore al gestore C di alto livello di default per la gestione della INVALID OPCODE       */

static struct info_patch info_patch_spurious;                       /* Struttura dati mantenente le informazioni per la binary patching della entry spuria          */
static struct info_patch info_patch_invalid_op;                     /* Struttura dati mantenente le informazioni per la binary patching della entry invalid opcode  */

unsigned long cr0;
static struct proc_dir_entry *my_proc_dir_entry;

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

static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

    int i;
    security_metadata *sm;
    unsigned long *end_of_stack;
#if defined(LOG_SYSTEM) || defined(IOCTL_INSTRUM_MAP)
    int ret;
    ht_item *item;
#endif
#ifdef LOG_SYSTEM
    char *program_name;
    log_system_info *lsi;
#endif
#ifdef IOCTL_INSTRUM_MAP
    size_t size;
    int error_value;
    unsigned long *ret_array;
    unsigned long *call_array;
    struct ioctl_data *my_ioctl_data;
#endif

    /*
     * The Security_Medata command allows you to allocate safety metadata for the current thread.
     * The IOCTL_INSTRUM_MAP command allows you to recover the instrument map to validate the
     * requests for calls and return from the user program.
     */

    switch(cmd) {

        case SECURITY_METADATA:

            /* I communicate the presence of a new thread that will perform in the architecture*/
            __sync_add_and_fetch(&num_threads, 1);

#ifdef DEBUG_IOCTL_FUNC
            pr_info("%s: [IOCTL] [%d] Request for allocation and initialization of safety metadata\n", MOD_NAME, current->pid);
#endif
            /* Recovery the base of the original kernel level stack                                                  */
            GET_KERNEL_STACK_BASE(end_of_stack);

            /*The thread cannot be described to avoid competition with the hook on the finish_task_switch()       */
            preempt_disable();

            /* Recovery the pointer to the safety metadata of the current thread                                       */
            GET_SECURITY_METADATA(end_of_stack, sm);

            /* Control any errors in the execution of finish_task_switch() hook                        */
            if(check_errore_finish_task_switch_hook(end_of_stack)) {
                pr_err("%s: [ERRORE IOCTL] [%d] An error occurred during the execution of the hook finish_task_switch()\n", MOD_NAME, current->pid);
                return -ENOMEM;
            }

            /* Check if the metadata have already been displayed through the hook on the finish_task_switch()             */

            if(end_of_stack[0] == (unsigned long)MAGIC_NUMBER && end_of_stack[2] == (unsigned long)MAGIC_NUMBER && (void *)sm != NULL) {

                /* The information to perform correct monitoring is missing only to recover from the Loader Elf   */

#ifdef IOCTL_INSTRUM_MAP
                /* The instrument map will be communicated subsequently by the Loader Elf via ioctl()        */
                sm->instrum_map = NULL;
#endif

#ifdef LOG_SYSTEM
                sm->buffer_log = NULL;
                sm->offset_log = 0;

                sm->stack_user_copy = false;

                /* Alloc the data structure to copy monitoring information                                   */
                lsi = (log_system_info *)kmalloc(sizeof(log_system_info), GFP_KERNEL);

                if((void *)lsi == NULL) {
                    preempt_enable();
                    pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of memory for monitoring information\n",
                    MOD_NAME,
                    current->pid);
                    return -ENOMEM;
                }

                /* Recovery of monitoring information for the new program                                        */
                ret = copy_from_user(lsi, (log_system_info *)arg, sizeof(log_system_info));

                if(ret) {
                    if((void *)lsi != NULL) kfree((void *)lsi);
                    preempt_enable();
                    pr_err("%s: [ERROR IOCTL] [%d] Reading error of monitoring information [byte Unread --> %d]\n",
                    MOD_NAME,
                    current->pid,
                    ret);
                    return -EFAULT;
                }

                /* Recovery the name of the new program that will be used to create the log file                   */

                program_name = (char *)kzalloc(lsi->len, GFP_KERNEL);

                if((void *)program_name == NULL) {
                    if((void *)lsi != NULL)                 kfree((void *)lsi);
                    preempt_enable();
                    pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of memory for the name of the new program\n",
                    MOD_NAME,
                    current->pid);
                    return -ENOMEM;
                }

                ret = copy_from_user(program_name, lsi->program_name, lsi->len);

                if(ret) {
                    if((void *)lsi != NULL)             kfree((void *)lsi);
                    if((void *)program_name != NULL)    kfree((void *)program_name);
                    preempt_enable();
                    pr_err("%s: [ERROR IOCTL] [%d] Error in reading the name of the new program [byte Unread --> %d]\n",
                    MOD_NAME,
                    current->pid,
                    ret);
                    return -EFAULT;
                }

                /*I check if the process identifier received is valid*/
                if(check_already_exists(program_name, lsi->id_user)) {
                    if((void *)lsi != NULL)             kfree((void *)lsi);
                    if((void *)program_name != NULL)    kfree((void *)program_name);
                    preempt_enable();
                    pr_err("%s: [ERRORE IOTCL] [%d] [0] L'identificativo scelto per il processo corrente è stato già utilizzato in precedenza\n",
                    MOD_NAME,
                    current->pid);
                    return -EINVAL;
                }

                lsi->program_name = program_name;

                /* I register the monitoring information between the safety metadata of the current thread                 */
                sm->lsi = lsi;

                /* Alloco the memory for the new element in the hash table                         */
                item = (ht_item *)kmalloc(sizeof(ht_item), GFP_KERNEL);

                if(item == NULL) {
                    if((void *)lsi != NULL)             kfree((void *)lsi);
                    if((void *)program_name != NULL)    kfree((void *)program_name);
                    preempt_enable();
                    pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of the element to be included in the hash table\n",
                    MOD_NAME,
                    current->pid);
                    return -ENOMEM;
                }
        
                /* So far only the main thread of the process has the reference to shared information         */
                item->reference_counter = 1;

                /* The process to which this information is associated is identified through its structure MM    */
                item->mm_address = (unsigned long)current->mm;

#ifdef IOCTL_INSTRUM_MAP
                /* This setting is used for the check that is done in the Hook on the Finish_task_Switch             */
                item->instrum_map_address = (unsigned long)NULL;
#endif
                /* Pointer to monitoring information including the base and data to create log files      */
                item->lsi = sm->lsi;

                /* I insert the element inside the hash table*/
                hash_add(ht_tesi, &(item->ht_list_next), item->mm_address);
#endif
                /*I become again de-firmable */
                preempt_enable();

#ifdef DEBUG_IOCTL_FUNC
                pr_info("%s: [IOCTL] [%d] I metadati di sicurezza sono stati già allocati ed inizializzati\n", MOD_NAME, current->pid);
#endif
                return 0;
            }

            /*
             * Setto the Magic Number to carry out checks on the state of the original Stack Kernel.This setting comes
             * performed immediately because if during recovery of the monitoring information there is an error and immediately after
             * The hook is performed then we realize the error through the check_error_security_medata () function.
             */
            end_of_stack[0] = (unsigned long)MAGIC_NUMBER;
            end_of_stack[2] = (unsigned long)MAGIC_NUMBER;

#ifdef LOG_SYSTEM

            /*
             * Before allocating and initializing the safety metadata check if the identification (program name, numerical ID)
             * passed by the user for this new process to be monitored has already been used previously.In this case, it is necessary to
             * Finish with an error the execution of the Loader Elf.I observe that during the execution of this code it is not possible
             * Having context changes that would overlap memory allocations with the hook on the Finish_task_Switch ().
             */


            /* Alloc the data structure to copy monitoring information                                   */
            lsi = (log_system_info *)kmalloc(sizeof(log_system_info), GFP_KERNEL);

            if((void *)lsi == NULL) {
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of memory for monitoring information\n",
                MOD_NAME,
                current->pid);
                return -ENOMEM;
            }

            /* Recovery of monitoring information for the new program                                       */
            ret = copy_from_user(lsi, (log_system_info *)arg, sizeof(log_system_info));

            if(ret) {
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                preempt_enable();
                pr_err("%s: [ERRORE IOCTL] [%d] Reading error of monitoring information [byte Unread --> %d]\n",
                MOD_NAME,
                current->pid,
                ret);
                return -EFAULT;
            }

            /* Recovery the name of the new program that will be used to create the log file                   */
            program_name = (char *)kzalloc(lsi->len, GFP_KERNEL);

            if((void *)program_name == NULL) {
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of memory for the name of the new program\n",
                MOD_NAME,
                current->pid);
                return -ENOMEM;
            }

            /* I read the name of the new program                                                                */
            ret = copy_from_user(program_name, lsi->program_name, lsi->len);

            if(ret) {
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in reading the name of the new program [byte Unread --> %d]\n",
                MOD_NAME,
                current->pid,
                ret);
                return -EFAULT;
            }

            /* I check the validity of the identification for the current process to be monitored chosen by the user */
            if(check_already_exists(program_name, lsi->id_user)) {
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
                preempt_enable();
                pr_err("%s: [ERROR IOTCL] [%d] [1] The identification chosen for the current process has already been used previously\n",
                MOD_NAME,
                current->pid);
                return -EINVAL;
            }

            /* I memorize the name of the executable of which the current process is an application                                 */
            lsi->program_name = program_name;

#endif //LOG_SYSTEM

            /* Alloc the memory for the data structure containing the security metadata by setting the value of the pointers to NULL */
            sm = (security_metadata *)kzalloc(sizeof(security_metadata), GFP_KERNEL);

            if((void *)sm == NULL) {
#ifdef LOG_SYSTEM
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
#endif
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of the data structure containing the safety metadata\n",
                MOD_NAME,
                current->pid);
                return -ENOMEM;
            }

            /* Setto the Magic Number to carry out checks on the status of safety metadata                */
            sm->magic_number = (unsigned long)MAGIC_NUMBER;

            /* The allocation of the structures given for the implementation of the new Kernel level stack begins...     */

            /* Alloco and initial the memory buffer to recover the elements of free stacks in time or (1)      */
            sm->free_items = (free_item *)kmalloc(STACK_SIZE_ARCH * sizeof(free_item), GFP_KERNEL);
    
            /*
             * The data structure containing the security metadata will be deallocated in the Hook on the Do_Exit () so
             * To identify the outgoing thread as belonging to our security architecture.
             */

            if(sm->free_items == NULL) {
#ifdef LOG_SYSTEM
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
#endif
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of the buffer for the search for free stack elements\n",
                MOD_NAME,
                current->pid);
                return -ENOMEM;
            }

            /* Each element on the connected list aims to the logically later element in the memory buffer    */
            for(i=0; i < STACK_SIZE_ARCH - 1;i++) {
                (sm->free_items)[i].next = &((sm->free_items)[i+1]);
            }

            /* Set the pointer at the head of the list of free stack elements (initially it is empty)        */
            sm->first_free_item = &((sm->free_items)[0]);

            /* Alloc the stack elements that will be included in the connected list that implements the stack       */
            sm->kernel_stack = (stack_item *)kmalloc(STACK_SIZE_ARCH * sizeof(stack_item), GFP_KERNEL);

            if(sm->kernel_stack == NULL) {
#ifdef LOG_SYSTEM
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
#endif
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of the buffer containing the stack elements\n",
                MOD_NAME,
                current->pid);
                return -ENOMEM;
            }

            /* Initially the new Kernel Stack does not contain any information: TOP = BASE                        */

            /* The base camp aims at the head of the closely connected list that implements the Kernel Stack        */
            sm->base = NULL;

            /* The top field points to the queue of the list doubly connected and represents the top of the stack       */
            sm->top = sm->base;

#ifdef MIX_ADDRESS
            sm->stack_frame_size_sum = 0;
            sm->num_stack_frame_pend = 0;

            sm->array_stack_pointers = (unsigned long *)kzalloc(sizeof(unsigned long) * STACK_SIZE_ARCH, GFP_KERNEL);

            if(sm->array_stack_pointers == NULL) {
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] ARRAY REGISTRATION ERROR CONTAINING THE END OF THE PULCIAL FRAMP STACKS\n",
                MOD_NAME,
                current->pid);
#ifdef LOG_SYSTEM
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
#endif
                return 0;   
            }

            sm->copy_stack_user = (unsigned char *)kmalloc(N, GFP_KERNEL);

            if(sm->copy_stack_user == NULL) {
                preempt_enable();
                pr_err("%s: [ERROR IOCTL] [%d] Error in the allocation of the buffer to store the copy of the user stack in validation\n",
                MOD_NAME,
                current->pid);
#ifdef LOG_SYSTEM
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
#endif
                return 0;   
            }
#endif

#ifdef IOCTL_INSTRUM_MAP
            /* The instrument map will be communicated subsequently by the Loader ELF via the IOCTL ()         */
            sm->instrum_map = NULL;
#endif

#ifdef LOG_SYSTEM
            sm->buffer_log = NULL;
            sm->offset_log = 0;

            /* Set the flag relating to the copy of the portion of the user stack */
            sm->stack_user_copy = false;

            /* I register the monitoring information between the safety metadata of the current thread                */
            sm->lsi = lsi;

            /*
             * At this point, the current thread has information for:
             * 1. Simulate the Return and Calls using the new Kernel level Stack.
             * 2. Take advantage of monitoring information to calculate the addresses that are parameters of events.
             * However, the main thread has information that can need any other threads of the same
             * process.To share this information, add a new element within the hash table.
             * Each element of the hash table is associated with a process launched within our archive.
             */

            /* Alloc the memory for the new element in the hash table                          */
            item = (ht_item *)kmalloc(sizeof(ht_item), GFP_KERNEL);

            if(item == NULL) {
                if((void *)lsi != NULL)                 kfree((void *)lsi);
                if((void *)program_name != NULL)        kfree((void *)program_name);
                preempt_enable();
                pr_err("%s: [ERRORE IOCTL] [%d] Errore allocazione elemento della hash table\n",
                MOD_NAME,
                current->pid);
                return -ENOMEM;
            }
        
            /* So far only the main thread of the process has the reference to shared information        */
            item->reference_counter = 1;

            /* The process to which this information is associated is identified through its MM structure    */
            item->mm_address = (unsigned long)current->mm;

#ifdef IOCTL_INSTRUM_MAP
            /* This setting is used for the check that is done in the Hook on the Finish_task_Switch            */
            item->instrum_map_address = (unsigned long)NULL;
#endif
            /* Pointer to monitoring information including the base and data to create log files      */
            item->lsi = sm->lsi;

            /* I insert the element inside the hash table */
            hash_add(ht_tesi, &(item->ht_list_next), item->mm_address);

#endif //LOG_SYSTEM

            /* Register on the original Kernel Stack the Safety metadata pointer                           */
            end_of_stack[1] = (unsigned long)sm;

            preempt_enable();

            break;


#ifdef IOCTL_INSTRUM_MAP
        case INSTRUM_MAP:

            int is_error;

#ifdef LOG_SYSTEM        
            int found;
            ht_item *data;
#endif

#ifdef DEBUG_IOCTL_FUNC
            pr_info("%s: [IOCTL] [%d] Attempt to recover the Map of Instrumentation Map user space...\n",
            MOD_NAME,
            current->pid);
#endif
            /* Recovery the base of the original kernel level stack                              */
            GET_KERNEL_STACK_BASE(end_of_stack);

            is_error = check_integrity_security_metadata(end_of_stack);

            /* I perform integrity checks for the original and metadata stack kernel          */
            if(is_error == 0) {
                pr_err("%s: [ERROR IOCTL] [%d] The original stack kernel or security metadata do not contain correct information\n",
                MOD_NAME,
                current->pid);
                error_value = -EINVAL; 
                goto map_error_1;
            }

            /* Recovery of the data structure containing the safety metadata                           */
            GET_SECURITY_METADATA(end_of_stack, sm);

            if((void *)sm->instrum_map != NULL) {
                pr_err("%s: [ERROR IOCTL] [%d] The instrument map would seem to have already been recovered\n",
                MOD_NAME,
                current->pid);
                error_value = -EINVAL; 
                goto map_error_1;
            }

            /* Instance the data structure that will contain the Information of Instrumentation Light Kernel */
            my_ioctl_data = (struct ioctl_data *)kmalloc(sizeof(struct ioctl_data), GFP_KERNEL);
    
            if((void *)my_ioctl_data == NULL) {
                pr_err("%s: [ERROR IOCTL] [%d] Error in memory allocation for the User Space Instrument Map\n",
                MOD_NAME,
                current->pid);
                error_value = -ENOMEM; 
                goto map_error_1;
            }          

            /*
             * I copy the data structure passing by the Loader Elf which contains:
             * - The number of instruated calls.
             * - The number of instruated RETs.
             * - The array containing the memory addresses of the Int 0xff instructions.
             * - The array containing the 0x06 byte memory addresses.
             * - Initial extreme of the instrumental memory area
             * - Extreme ending of the instrumental memory area
             * Since the two arms are pointers to other areas of memory, it is also necessary to copy the data that is focused.
             */

            ret = copy_from_user(my_ioctl_data, (struct ioctl_data *)arg, sizeof(struct ioctl_data));

            if(ret) {
                pr_err("%s: [ERROR IOCTL] [%d] Reading error of the User Space Instrument Map[byte Unread --> %d]\n",
                MOD_NAME,
                current->pid,
                ret);
                error_value = -EFAULT; 
                goto map_error_2;
            }

#ifdef DEBUG_IOCTL_FUNC
            pr_info("%s: [IOCTL] [%d] Number of CALL = %d\tNumber of RET = %d\n",MOD_NAME, current->pid, my_ioctl_data->call_num, my_ioctl_data->ret_num);
#endif

            /* Recovery of the memory addresses of the Instructions Int 0xff inserted by the Loader Elf */
            if(my_ioctl_data->call_num == 0) {
                my_ioctl_data->call_array = NULL;
                goto no_call;
            }

            /* Calculation the size of the array containing the addresses of the INSTRUCTIONS INST 0XFFF */
            size = sizeof(unsigned long) * my_ioctl_data->call_num;

            call_array = (unsigned long *)kmalloc(size, GFP_KERNEL);

            if(call_array == NULL) {
                pr_err("%s: [ERROR IOCTL] [%d] ARray memory allocation error containing the instructions memory addressesINT 0xFF\n",
                MOD_NAME,
                current->pid);
                error_value = -ENOMEM; 
                goto map_error_2;
            }            

            /* I copy the array with memory addresses */
            ret = copy_from_user(call_array, (unsigned long *)my_ioctl_data->call_array, size);

            if(ret) {
                pr_err("%s: [ERROR IOCTL] [%d] Error in reading the addresses of the instructions INT 0xFF [byte Unread --> %d]\n",
                MOD_NAME,
                current->pid,
                ret);
                error_value = -EFAULT; 
                goto map_error_3;
            }

            my_ioctl_data->call_array = call_array;

#ifdef DEBUG_IOCTL_FUNC
            /* I mold the addresses of the INSTRUCTIONS INST 0XFFS included by the ELF Loader */
            for(i=0; i<my_ioctl_data->call_num; i++) {
                pr_info("%s: [IOCTL] [%d]Instruction address INT 0xFF #%d: %px\n",
                MOD_NAME,
                current->pid,
                i,
                (void *)((my_ioctl_data->call_array)[i]));
            }
#endif

no_call:
            /* Recovery of the 0x06 byte memory addresses inserted by the Loader Elf */
            if(my_ioctl_data->ret_num == 0) {
                my_ioctl_data->ret_array = NULL;
                goto no_ret;
            }
            
            /* Calculation the size of the array of the addresses of the 0x06 bytes to be allocated*/
            size = sizeof(unsigned long) *  my_ioctl_data->ret_num;

            ret_array = (unsigned long *)kmalloc(size, GFP_KERNEL);

            if(ret_array == NULL) {
                pr_err("%s: [ERROR IOCTL] [%d] Memory allocation error for the array containing the memory addresses of the bytes 0x06\n",
                MOD_NAME,
                current->pid);
                error_value = -ENOMEM; 
                goto map_error_3;
            }

            /* I copy the array with memory addresses*/
            ret = copy_from_user(ret_array, (unsigned long *)my_ioctl_data->ret_array, size);

            if(ret) {
                pr_err("%s: [ERROR IOCTL] [%d] Error in reading the addresses of the bytes 0x06 [byte Unread --> %d]\n",
                MOD_NAME,
                current->pid,
                ret);
                error_value = -EFAULT; 
                goto map_error_4;
            }

            my_ioctl_data->ret_array = ret_array;

#ifdef DEBUG_IOCTL_FUNC
            /* I mold the addresses of the INSTRUCTIONS INT 0XFF included by the ELF Loader */
            for(i=0; i<my_ioctl_data->ret_num; i++) {
                pr_info("%s: [IOCTL] [%d] Address of the byte 0x06 #%d: %px\n",
                MOD_NAME,
                current->pid,
                i,
                (void *)((my_ioctl_data->ret_array)[i]));
            }
#endif

no_ret:

#ifdef DEBUG_IOCTL_FUNC
            pr_info("%s: [IOCTL] [%d] The extremes of the instrument area are [%px, %px]\n", MOD_NAME, current->pid,
            (void *)my_ioctl_data->start_text,  
            (void *)my_ioctl_data->end_text);
#endif

            /* Set the pointer to the tentrous map in safety metadata         */
            sm->instrum_map = my_ioctl_data;

#ifdef LOG_SYSTEM

            /*
             * The element was inserted in the hash table through the Security_Medata and non -Security command
             * must be inserted again.To share the instrument map with others
             * process of the process I receive the element in the hash table corresponding to the structure of
             * Mm of the current thread and memorize the reference to the instrument map.
             */

            found = 0;

            hash_for_each_possible(ht_tesi, data, ht_list_next, (unsigned long)current->mm) {
            
                /* I check if the current element is associated with the current thread mm */
                if((unsigned long)data->mm_address == (unsigned long)current->mm) {

                    /* I share the instrument map with the other threads of the same process */
                    data->instrum_map_address = (unsigned long)my_ioctl_data;
#ifdef DEBUG_IOCTL_FUNC
                    pr_info("%s: [IOCTL] [%d] Setting of the instrument map successful in the hash table\n",
                    MOD_NAME,
                    current->pid);
#endif //DEBUG_IOCTL_FUNC
                    found = 1;

                    break;
                }
            }

            if(!found) {
                pr_err("%s: [ERROR IOCTL] [%d] Error in the search for the element inside the hash table\n",
                MOD_NAME,
                current->pid);
                error_value = -EINVAL; 
                goto map_error_4;
            }
#else
            /* I insert a new element inside the hash table to share the map with the other threads*/
            item = (ht_item *)kmalloc(sizeof(ht_item), GFP_KERNEL);

            if(item == NULL) {
                pr_err("%s: [ERROR IOCTL] [%d] Hash Table element error\n", MOD_NAME, current->pid);
                error_value = -ENOMEM; 
                goto map_error_4;
            }
        
            /* Until only only the main thread of the application has the reference to the instrument map */
            item->reference_counter = 1;

            /* I memorize the address of the MM structure for the current thread */
            item->mm_address = (unsigned long)current->mm;

            /* Pointer at the Map of Instrumentation*/
            item->instrum_map_address = (unsigned long)my_ioctl_data;

            /* I insert the element inside the hash table */
            hash_add(ht_tesi, &(item->ht_list_next), item->mm_address);
#endif //LOG_SYSTEM

            break;
#endif       
    
        default:
            pr_err("%s: [ERROR IOCTL] The command passed in input is not valid\n", MOD_NAME);
            return -EINVAL;
    }

    return 0;


#ifdef IOCTL_INSTRUM_MAP

/* Gestione degli errori */
map_error_4:
    if((void *)ret_array != NULL)           kfree((void *)ret_array);

map_error_3:
    if((void *)call_array != NULL)          kfree((void *)call_array);

map_error_2:
    if((void *)my_ioctl_data != NULL)       kfree((void *)my_ioctl_data);

map_error_1:

#ifdef LOG_SYSTEM
    /* If the monitoring system is active, then an element in the HT_Tesi has been included in the previous command*/
    delete_ht_item();
#endif

    return error_value;
#endif

}

/* File Operations associate al nodo in /proc */
struct proc_ops proc_fops = {
  .proc_ioctl = my_ioctl
};



