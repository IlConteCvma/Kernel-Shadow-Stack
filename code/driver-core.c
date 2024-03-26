#include "includes/dirver-core.h"
#include "includes/module-defines.h"
#include "includes/utils.h"
#include "includes/kss_struct.h"
#include "includes/hooks.h"
#include "includes/my_ioctl.h"
#include "includes/kss_hashtable.h"
#include "includes/logging.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Calavaro");
MODULE_DESCRIPTION("Kernel shadow stack module");
MODULE_VERSION("1.0");

//functions
int kss_module_init(void);
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void kss_module_exit(void);

int num_threads = 0;

sysvec_spurious_apic_interrupt_t sysvec_spurious_apic_interrupt;    /* Pointer to the Co -High level C manager for the management of the disasters of the spuries interrupt  */
exc_invalid_op_t exc_invalid_op;                                    /* Top leader C manager of high level of default for the management of the INVALID OPCODE       */

static struct info_patch info_patch_spurious;                       /* Data structure maintaining information for the entry spuria binary patching          */
static struct info_patch info_patch_invalid_op;                     /* Data structure maintaining information for the Binary Patching of Entry Invalid Opcode  */


static struct proc_dir_entry *my_proc_dir_entry;



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
            if(check_error_finish_task_switch_hook(end_of_stack)) {
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



int kss_module_init(void) {

    int ret;
    gate_desc *idt;                                                                                         /* Pointer to the IDT table                    */
    struct desc_ptr dtr;                                                                                    /* Pointer to the information of the IDT table   */
    unsigned long asm_sysvec_spurious_apic_interrupt_addr;                                                  /* ASM Handler #255 corretto                       */
    unsigned long sysvec_spurious_apic_interrupt_addr;                                                      /* C Handler   #255 corretto                       */
    unsigned long addr_spurious_first_handler;                                                              /* ASM Handler #255 effettivo                      */
    unsigned long asm_exc_invalid_op_addr;                                                                  /* ASM Handler #6 corretto                         */
    unsigned long exc_invalid_op_addr;                                                                      /* C Handler   #6 corretto                         */
    unsigned long addr_invalid_op_first_handler;                                                            /* ASM Handler #6 effettivo                        */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    kallsyms_lookup_name_t kallsyms_lookup_name;                                                            /* Address of the function kallsyms_lookup_name() */
#endif

    
    /* I read the content of the register IDTR             */
    store_idt(&dtr);               

    /* Recovery the address of the table IDT           */                                                                         
    idt = (gate_desc *)dtr.address;

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [%d] The address of the table IDT is  %px\n",MOD_NAME, current->pid, (void *)idt);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    /* Recovery the memory address of the Kallsyms_lookup_name () function */
    kallsyms_lookup_name = get_kallsyms_lookup_name();

    if(kallsyms_lookup_name == NULL) {
        pr_err("%s: [ERROR MODULE INIT] [%d] Error in recovering function kallsyms_lookup_name()\n", MOD_NAME, current->pid);
        return -1;
    }

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [%d] The function kallsyms_lookup_name() It is present at the memory address %px\n",
            MOD_NAME, current->pid,
            (void *)kallsyms_lookup_name);
#endif
#endif

    /* Recovery the manager's memory address ASM #255 correct */
    asm_sysvec_spurious_apic_interrupt_addr = kallsyms_lookup_name("asm_sysvec_spurious_apic_interrupt");

    /* Recovery the manager's memory address C   #255 correct */
    sysvec_spurious_apic_interrupt_addr = kallsyms_lookup_name("sysvec_spurious_apic_interrupt");

    /* I check the validity of the addresses found                 */
    if(asm_sysvec_spurious_apic_interrupt_addr == 0 || sysvec_spurious_apic_interrupt_addr == 0) {
        pr_err("%s: [ERROR MODULE INIT] [%d] It is not possible to recover the addresses of the managers for the Spuria interrupt\n", MOD_NAME, current->pid);
        return -1;    
    }

    /* I define the high -level CPurpT high -level management function */
    sysvec_spurious_apic_interrupt = (sysvec_spurious_apic_interrupt_t)sysvec_spurious_apic_interrupt_addr;

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [SPURIOUS] [%d] asm_sysvec_spurious_apic_interrupt --> %px\t"
            "sysvec_spurious_apic_interrupt --> %px\n",
            MOD_NAME, current->pid,
            (void *)asm_sysvec_spurious_apic_interrupt_addr,
            (void *)sysvec_spurious_apic_interrupt_addr);
#endif

    /* Recovery the address of the actual ASM manager in the descriptor of the IDT */
    addr_spurious_first_handler = get_full_offset_spurious_interrput(idt);

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [SPURIOUS] [%d] Effective Handler Asm is located at the address %px\n",
            MOD_NAME, current->pid,
            (void *)addr_spurious_first_handler);
#endif

    /* I check if the actual ASM manager corresponds to the correct ASM manager */
    if(addr_spurious_first_handler != asm_sysvec_spurious_apic_interrupt_addr) {
        pr_err("%s: [ERROR MODULE INIT] [SPURIOUS] [%d] Matching missed on the address of the first level ASM manager\n",
               MOD_NAME,
               current->pid);
        return -1;
    }

    /*
     * At this point, I am sure that the ASM manager recorded in the IDT table
     * corresponds to the correct Asm manager.At this point, we are looking for in the manager's code
     * Asm the call to the correct high -level C manager in order to modify it by pointing it
     * to our new high -level C manager.
     */

    ret = patch_IDT(addr_spurious_first_handler, sysvec_spurious_apic_interrupt_addr, dtr, SPURIOUS_APIC_VECTOR, my_spurious_handler, &info_patch_spurious); 

    if(!ret) {
        pr_err("%s: [ERROR MODULE INIT] [SPURIOUS] [%d] It was not possible to perform the binary patch for the entry #%d\n",
               MOD_NAME,
               current->pid,
               SPURIOUS_APIC_VECTOR);
        return -1;
    }

    /* Recovery the manager's memory address ASM #6  correct */
    asm_exc_invalid_op_addr = kallsyms_lookup_name("asm_exc_invalid_op");

    /* Recovery the manager's memory address C   #6  correct */
    exc_invalid_op_addr = kallsyms_lookup_name("exc_invalid_op");

    /* I check the validity of the addresses found                */
    if(asm_exc_invalid_op_addr == 0 || exc_invalid_op_addr == 0) {
        pr_err("%s: [ERROR MODULE INIT] [%d] It is not possible to recover the guidelines of the managers for Invalid Opcode\n",
                MOD_NAME,
                current->pid);
        goto error_idt_1;
    }

    /* I define the high -level Cvalid OPCODE management function */
    exc_invalid_op = (exc_invalid_op_t)exc_invalid_op_addr;

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [INVALID OPCODE] [%d] asm_exc_invalid_op --> %px\t"
            "exc_invalid_op --> %px\n",
            MOD_NAME, current->pid,
            (void *)asm_exc_invalid_op_addr,
            (void *)exc_invalid_op_addr);
#endif

    /* Recovery the virtual address of the manager asm #6 effective */
    addr_invalid_op_first_handler = get_full_offset_invalid_opcode(idt); 

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [INVALID OPCODE] [%d] The actual Handler Asm is located at the address %px\n",
            MOD_NAME, current->pid,
            (void *)addr_invalid_op_first_handler);
#endif

    /* I check if the actual ASM manager corresponds to the correct ASM manager */
    if(addr_invalid_op_first_handler != asm_exc_invalid_op_addr)
    {
        pr_err("%s: [ERROR MODULE INIT] [INVALID OPCODE] [%d] Matching missed on the address of the first level manager\n", MOD_NAME, current->pid);
        goto error_idt_1;
    }

    ret = patch_IDT(addr_invalid_op_first_handler, exc_invalid_op_addr, dtr, X86_TRAP_UD, my_invalid_op_handler, &info_patch_invalid_op);

    if(!ret) {
        pr_err("%s: [ERROR MODULE INIT] [INVALID OPCODE] [%d] It was not possible to perform the binary patch for the entry #%d\n", MOD_NAME, current->pid, X86_TRAP_UD);
        goto error_idt_1;
    }

    /* Recovery the function do_group_exit()                         */
    do_group_exit_addr = (do_group_exit_t)kallsyms_lookup_name("do_group_exit");

    if(do_group_exit_addr == NULL) {
        pr_err("%s: [ERROR MODULE INIT] [%d] It was not possible to recover the address of the function do_group_exit()\n", MOD_NAME, current->pid);
        goto error_idt_2;
    }

    /*
     * The allocation and deallocation of the new Kernel Per-Thread level Stack must be
     * carried out in correspondence with the execution of specific functions.The deallocation takes place
     * at the beginning of the Do_Exit () function while allocation takes place at the beginning of the function
     * Finish_task_Switch ().
     */

    ret = install_kprobes();

    if(!ret) {
        pr_err("%s: [ERROR MODULE INIT] [%d] Error in the installation of the Hooks\n", MOD_NAME, current->pid);
        goto error_idt_2;
    }

#ifdef LOG_SYSTEM
    /*
     * I create a Workqueue in which the work for the asynchronous writing of events will be inserted
     * and the portion of corrupt user stack on log files.
     */

    wq = alloc_ordered_workqueue(workqueue_name, 0);

    if(!wq) {
        pr_err("%s: [MODULE INIT] [%d] Error in creating workqueue\n", MOD_NAME, current->pid);
        goto error_kprobe;
    }

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [%d] Workqueue was successfully created\n", MOD_NAME, current->pid);
#endif
  
#endif

    /* Creation of the node in /proc */
    my_proc_dir_entry = proc_create("tesi_node", 0666, NULL, &proc_fops);

    if(!my_proc_dir_entry) {
        pr_err("%s: [ERROR MODULE INIT] [%d] Failed attempt to create a new knot in /proc\n", MOD_NAME, current->pid);
#ifdef LOG_SYSTEM
        goto error_log;
#else
        goto error_kprobe;
#endif
    }

#ifdef INFO_DEBUG
    pr_info("%s: [MODULE INIT] [%d] The new knot /proc/%s it was successfully created\n", MOD_NAME, current->pid, "tesi_node");
#endif

    return 0;

#ifdef LOG_SYSTEM
error_log:
    destroy_workqueue(wq);
#endif

error_kprobe:
    unregister_kprobe(&kp_kernel_clone);
    unregister_kprobe(&kp_finish_task_switch);
    unregister_kprobe(&kp_finish_task_switch_cold);
    unregister_kprobe(&kp_do_exit);

error_idt_2:
    cr0 = read_cr0();
	unprotect_memory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    arch_cmpxchg(info_patch_invalid_op.call_operand_address, info_patch_invalid_op.new_call_operand, info_patch_invalid_op.old_call_operand);
#else
    cmpxchg(info_patch_invalid_op.call_operand_address, info_patch_invalid_op.new_call_operand, info_patch_invalid_op.old_call_operand);
#endif
    write_idt_entry((gate_desc*)dtr.address, X86_TRAP_UD, &(info_patch_invalid_op.old_entry));
    protect_memory();

error_idt_1:
    cr0 = read_cr0();
	unprotect_memory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    arch_cmpxchg(info_patch_spurious.call_operand_address, info_patch_spurious.new_call_operand, info_patch_spurious.old_call_operand);
#else
    cmpxchg(info_patch_spurious.call_operand_address, info_patch_spurious.new_call_operand, info_patch_spurious.old_call_operand);
#endif
    write_idt_entry((gate_desc*)dtr.address, SPURIOUS_APIC_VECTOR, &(info_patch_spurious.old_entry));
    protect_memory();

return -1;

}


void kss_module_exit(void) {

	struct desc_ptr idtr;

    /*
     * I remove the node in /proc in order to block the launch of new processes within the architecture.
     * The invocation of the IOCTL () command () on the in /proc node will end with an error.If it should be verified
     * An error, then the Loader Elf would end its execution without passing control to the new
     * plan.
     */

    proc_remove(my_proc_dir_entry);

    pr_info("%s: [MODULE EXIT] [%d] The knot /proc/%s it was successfully removed\n",
             MOD_NAME,
             current->pid,
             "tesi_node");

    /*I await that all the threads that have already been launched by the Loader Elf of architecture end their execution*/

redo_exit:

    if(num_threads) {
        msleep(PERIOD * 1000);
        goto redo_exit;
    }

    store_idt(&idtr);

    cr0 = read_cr0();
	unprotect_memory();

    

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    arch_cmpxchg(info_patch_spurious.call_operand_address, info_patch_spurious.new_call_operand, info_patch_spurious.old_call_operand);
    arch_cmpxchg(info_patch_invalid_op.call_operand_address, info_patch_invalid_op.new_call_operand, info_patch_invalid_op.old_call_operand);
#else
    cmpxchg(info_patch_spurious.call_operand_address, info_patch_spurious.new_call_operand, info_patch_spurious.old_call_operand);
    cmpxchg(info_patch_invalid_op.call_operand_address, info_patch_invalid_op.new_call_operand, info_patch_invalid_op.old_call_operand);
#endif

    pr_info("%s: [MODULE EXIT] [%d] Binary patches on ASM managers have been successfully restored\n",
    MOD_NAME,
    current->pid);

    /* Restore the descriptors of the table IDT in order to report the DPL at zero value */

	write_idt_entry((gate_desc*)idtr.address, SPURIOUS_APIC_VECTOR, &(info_patch_spurious.old_entry));
    write_idt_entry((gate_desc*)idtr.address, X86_TRAP_UD, &(info_patch_invalid_op.old_entry));

    pr_info("%s: [MODULE EXIT] [%d] IDT descriptors were successfully reset\n",
    MOD_NAME,
    current->pid);

	protect_memory();

    /* I remove the recordings of the KPROBE */
    unregister_kprobe(&kp_kernel_clone);
    unregister_kprobe(&kp_finish_task_switch);
    unregister_kprobe(&kp_finish_task_switch_cold);
    unregister_kprobe(&kp_do_exit);

    pr_info("%s: [MODULE EXIT] [%d] The proe kernels were successfully removed\n",
    MOD_NAME,
    current->pid);

#ifdef LOG_SYSTEM
    /* Delete the world by reporting pending events on log files */
    destroy_workqueue(wq);

    pr_info("%s: [MODULE EXIT] [%d] Workqueue was successfully removed\n",
    MOD_NAME,
    current->pid);
#endif

    pr_info("%s: [MODULE EXIT] [%d] Il modulo kernel è stato rimosso con successo\n",
    MOD_NAME,
    current->pid);
}

module_init(kss_module_init);
module_exit(kss_module_exit);