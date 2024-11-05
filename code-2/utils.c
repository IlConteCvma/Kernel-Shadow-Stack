#include "includes/utils.h"
//#include "includes/module-defines.h"


#include <linux/kprobes.h>
#include <asm/trapnr.h>


//Global var
unsigned long cr0;

/* The offset avoids the overwriting of the possible thread_info structure in the original Stack Kernel                 */
#ifdef CONFIG_THREAD_INFO_IN_TASK
int offset_thread_info = sizeof(struct thread_info);
#else
int offset_thread_info = 0; 
#endif

/**
 * get_absolute_pathname - obtains the name of the executable program of which the process is currently in
 * execution.
 *
 * @buf: Buffer where the absolute pathname is written
 *
 * @return: returns the name of the executable program of which the process is currently running in case
 * successfull;Otherwise, it returns the Error Code -enoent (no file or directory).
 */
char *get_absolute_pathname(char *buf) {

    int size;
    struct file *exe_file;
    struct task_struct *task;


    task = current;

    /* Control if the current thread has the valid memory management structure */
    if(task->mm == NULL) {
        return ERR_PTR(-ENOENT);
    }

    exe_file = task->mm->exe_file;

    if(exe_file) {
        strncpy(buf, exe_file->f_path.dentry->d_iname, strlen(exe_file->f_path.dentry->d_iname));
        size = strlen(exe_file->f_path.dentry->d_iname);
        buf[size] = '\0';
    }

    return buf;    
}

// FILE UTILS --------------------

/**
 * init_log -Opening of the log file associated with the thread whose information must be reported.
 *
 * @Filename: name of the log file
 *
 * @return: returns the pointer to the I/O session on the log file in case of success;otherwise,
 * Returns an error code.
 */
struct file *init_log(char *filename) {

    struct file *file;


    file = filp_open((const char *)filename, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);

    /* Error code 17 represents EEXIST */
    if(IS_ERR(file)) {
        if(PTR_ERR(file) == -17) {
            pr_err("%s: [Log file opening error] [%d] The log file already exists\n",
            MOD_NAME,
            current->pid);
        } else {
            pr_err("%s: [ELog file opening error] [%d] Unable to open the log file'%s' For the current thread [error code: %ld]\n",
            MOD_NAME,
            current->pid,
            filename,
            PTR_ERR(file));
        }
    }

    return file;
}

/**
 * close_log -Closing of the log file.
 *
 * @File: pointer at the i/o session of the log file that you want to close
 */
void close_log(struct file *file) {
    filp_close(file, NULL);
}

/**
 * Kill_Process - The execution of the entire process ends.
 *
 * This function can be invoked when an abnormal system behavior occurs.
 * When a process of the process generates an event of 'corrupt user stack' then the whole process can
 * be finished.
 */
void kill_process(void) {
    pr_info("%s: [KILL PROCESS] [%d] Termination of the entire process in progress...\n", MOD_NAME, current->pid);
    do_group_exit_addr((1 & 0xFF)<<8);
}


/**
 * is_FF_call - Check if the machine education is a call with 0xff operating code.
 *
 * @istr_addr: Machine education address
 *
 * @return: return the value 1 if there is a 0xff call;otherwise, returns
 * The value 0.
 */
int is_FF_call(unsigned char *instr_addr) {

    int i;
    int found;
    unsigned char byte;


    /* I start with the idea of not having found any CALL 0xFF    */
    found = 0;

    /*
     * Research the first 0xff byte starting from 7 bytes before.I observe they exist
     * of bytes who are not candidates to represent the beginning of an instruction
     * of Call.More precisely, there are no call instructions codified with a
     * Single byte or with five bytes.After the 0xff opcode, a
     * further bytes that extends the operating code.To increase safety
     * occurs if the REG field of this byte (the 3 central bits) assume the
     * value 2 or 3.
     */

    for(i = 0; i < 7; i++) {
    
        /* I do not consider the positions in which there can be no start of a call */
        if(i == 2 || i == 6) continue;

        if(instr_addr[i] == 0xFF) {
        
            /* I check the next byte that extends the opcode                */

            /*Recovery the byte following the possible start of the call        */
            byte = instr_addr[i+1];

            /* Recovery the contents of the REG camp                          */
            byte = byte & IS_FF_REG;

            if((byte >> 3) == 2 || (byte >> 3) == 3) {
                found = 1;
                break;
            }            
            
        }
    }

    return found;
}

/**
 * is_E8_call - Check if the machine education is a call with 0xe8 operating code.
 *
 * @istr_addr: Machine education address
 *
 * @return: return the value 1 if there is a valid 0x8 call;otherwise, returns
 * The value 0.
 */
int is_E8_call(unsigned char *instr_addr) {

    if(instr_addr[2] == 0xE8)   return 1;

    return 0;
}

/**
 * check_call_security - Check if the machine instruction prior to that at the address of
 * Memory @ret_addr_user is a call.There are different types of calls but the maximum number
 * of bytes that can be used for coding a call instruction is equal to 7
 * (excluding the prefix bytes).
 *
 * @ret_addr_user: return address from which you would like to resume user execution
 *
 * @return: returns the value 0 if the previous education is a call;returns the value
 * 1 If the previous instruction is not a call;otherwise, returns in case of error the
 * value -1.
 */
int check_call_security(unsigned char *ret_addr_user) {
    
    int ret;
    unsigned char byte[7];

    /* Recovery the maximum number of bytes with which you can codify a call */
    ret = copy_from_user(byte, ret_addr_user - 7, 7);

    /* I check if an error has occurred in reading byte */
    if(ret) {
        pr_err("%s: [ERROR INVALID OPCODE CHECK CALL] [%d] Error in the recovery of the previous machine education in the user space [byte Unread --> %d]\n",
        MOD_NAME,
        current->pid,
        ret);
        return -1;
    }

    /* I check if the previous machine instruction is a type of call */
    if(is_E8_call(byte) || is_FF_call(byte))    return 0;

    return 1;
}

#ifdef IOCTL_INSTRUM_MAP
/**
 * check_0x06 - Check if the 0x06 byte present at the memory address @ret_instr_addr was
 * Posted by the Loader Elf.The bytes inserted by the Loader Elf are recorded in the instrument map.
 *
 * @ret_instr_addr: memory address of the byte 0x06
 * @SM: Poller to the safety metadata of the current thread
 *
 * @return: returns the value 1 if the 0x06 byte has been inserted by the Loader Elf;otherwise,
 * Returns the value 0.
 */
int check_0x06(unsigned long ret_instr_addr, security_metadata *sm) {

    int i;
    int ret_num;
    unsigned long *map_0x06;
    struct ioctl_data *map;


    /* I perform minimal correctness controls on the data structure */
    if(sm == NULL || sm->magic_number != (unsigned long)MAGIC_NUMBER) {
        pr_err("%s: [INVALID OPCODE HOOK][ERRORE CHECK 0x06][%d] The safety metadata were not stored on the original Stack Kernel\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

    /* Recovery the pointer to the instrument map              */
    map = sm->instrum_map;

    if(map == NULL) {
        return 1;
    }

    /*Recovery the Map of Instrumentation for the 0x06 bytes */
    map_0x06 = map->ret_array;

    /* Recovery of the size of the instrument map for byte 0x06 */
    ret_num = map->ret_num;

    /*
     * Se map_0x06 == NULL è vera allora significa che il Loader ELF non ha instrumentato alcuna
     * istruzione di RET. Di conseguenza, non è possibile che sia giunta al Kernel una richiesta di
     * simulazione di RET.
     */


    if((void *)map_0x06 == NULL && ret_num == 0) {
        pr_err("%s: [ERRORE CHECK 0x06] The map does not exist.In the Address Space there is a 0x06 byte that has not been inserted by the Loader Elf\n", MOD_NAME);
        return 0;
    } else if((void *)map_0x06 == NULL && ret_num != 0) {
        pr_err("%s: [ERRORE CHECK 0x06] The 0x06 byte map is not present in memory but there are Rets instructed by the Loader Elf\n", MOD_NAME);
        return 0;
    } else if((void *)map_0x06 != NULL && ret_num == 0) {
        pr_err("%s: [ERRORE CHECK 0x06] The 0x06 byte map is present in memory but there are no RETs instructed by the Loader Elf\n", MOD_NAME);
        return 0;
    }

    for(i=0; i<ret_num; i++) {

        if(map_0x06[i] == ret_instr_addr) {
#ifdef DEBUG_IOCTL_FUNC
            pr_info("%s: [CHECK 0x06] The 0x06 byte by address %px It was added by the Loader Elf\n",
            MOD_NAME,
            (void *)ret_instr_addr);
#endif
            return 1;
        }
    }

#ifdef DEBUG_IOCTL_FUNC
    pr_info("%s: [ERRORE CHECK 0x06]The 0x06 byte by address %px It was not added by the Loader Elf\n",
    MOD_NAME,
    (void *)ret_instr_addr);
#endif

    return 0;
}

/**
 * Check_int_0xff - Check if the INSTRUCTION INT 0XFF present at the memory address @call_instr_addr is
 * has been inserted by the Loader Elf.
 *
 * @call_instr_addr: Memory address of the Int 0xff instruction
 * @sm: Safety metadata pointer
 *
 * @return: returns the value 1 if the address of the Education of Int 0xff is valid;otherwise,
 * Returns the value 0.
 */
int check_int_0xFF(unsigned long call_instr_addr, security_metadata *sm) {

    int i;
    int call_num;
    unsigned long *map_int_0xFF;
    struct ioctl_data *map;


    /* We perform consistency checks on safety metadata to be used*/
    if(sm == NULL || sm->magic_number != (unsigned long)MAGIC_NUMBER) {
        pr_err("%s: [ERROR CHECK INT 0xFF][%d] The safety metadata were not stored on the original kernel stack \n",
        MOD_NAME,
        current->pid);
        return 0;
    }

    /* Recovery of the trend in the process associated with the process to which the current thread belongs*/
    map = sm->instrum_map;

    if(map == NULL) {
        return 1;
    }

    /* Recovery of the instrument map for INSTRUCTIONS INT 0XFF*/
    map_int_0xFF = map->call_array;

    /* Recovery of the size of the instrument to instructions for instructions INT 0xFF */
    call_num = map->call_num;

    if((void *)map_int_0xFF == NULL && call_num == 0) {
        pr_err("%s: [ERROR CHECK INT 0xFF] The map does not exist.In the Address Space there is one INT 0xFF which was not inserted by the Loader Elf\n", MOD_NAME);
        return 0;
    } else if((void *)map_int_0xFF == NULL && call_num != 0) {
        pr_err("%s: [ERROR CHECK INT 0xFF] The Int 0xff map is not present in memory but there are institled calls from the Loader Elf\n", MOD_NAME);
        return 0;
    } else if((void *)map_int_0xFF != NULL && call_num == 0) {
        pr_err("%s: [ERROR CHECK INT 0xFF] The Int 0xff map is present in memory but there are no instance calls by the Loader Elf\n", MOD_NAME);
        return 0;
    }

    /* Itero on the addresses of the Instructions Int 0xff that are present in the instrument map */
    for(i=0; i<call_num; i++) {
        if(map_int_0xFF[i] == call_instr_addr) {
#ifdef DEBUG_IOCTL_FUNC
            pr_info("%s: [CHECK INT 0xFF] Instruction Int 0xff at address %px It was added by the Loader Elf\n",
            MOD_NAME,
            (void *)call_instr_addr);
#endif
            return 1;
        }
    }

#ifdef DEBUG_IOCTL_FUNC
    pr_info("%s: [ERRORE CHECK INT 0xFF] Instruction Int 0xff at address %px It was not added by the Loader Elf\n",
    MOD_NAME,
    (void *)call_instr_addr);
#endif

    return 0;
}
#endif


/**
 * get_full_offset_by_vector - Calculate the memory address of the manager associated with the number
 * of vector required.
 *
 * @idt: memory address of the IDT table
 * @vector_number: numerical identification of the entry in the IDT target table
 *
 * @return: returns the memory address of the Asm manager corresponded to the entry in the
 * IDT Table Request.
 */
unsigned long get_full_offset_by_vector(gate_desc *idt, int vector_number) {

    gate_desc *gate_ptr;


    gate_ptr = (gate_desc *)((unsigned long)idt + vector_number * sizeof(gate_desc));
    return (unsigned long)HML_TO_ADDR(gate_ptr->offset_high,
                                      gate_ptr->offset_middle,
                                      gate_ptr->offset_low);
}

/**
 * get_full_offset_spurious_interrput - Recovers the memory address of the Asm Associate Manager
 * to entry spuria.
 *
 * @idt: memory address of the IDT table
 *
 * @return: the memory address of the Asm manager associated with entry spuria remains remained.
 */
unsigned long get_full_offset_spurious_interrput(gate_desc *idt) {  
  
    unsigned long address;


    address = get_full_offset_by_vector(idt, SPURIOUS_APIC_VECTOR);
    return address;
}


/**
 * get_full_offset_invalid_opcode - Recovers the memory address of the Asm Associate Manager
 * to the Invalid Opcode event.
 *
 * @idt: memory address of the IDT table
 *
 * @return: the memory address of the Asm manager associated with the
 * Entry Invalid Opcode.
 */
unsigned long get_full_offset_invalid_opcode(gate_desc *idt) {
  
    unsigned long address;


    address = get_full_offset_by_vector(idt, X86_TRAP_UD);
    return address;
}


