/*INCLUDES*/

#include "includes/utils.h"
#include "includes/hooks.h"

/*DEFINITION*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Calavaro");
MODULE_DESCRIPTION("Kernel shadow stack module");
MODULE_VERSION("1.0");

/*Functions*/
int kss_module_init(void);
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void kss_module_exit(void);


/*Variable*/
sysvec_spurious_apic_interrupt_t sysvec_spurious_apic_interrupt;    /* Pointer to the Co -High level C manager for the management of the disasters of the spuries interrupt  */


/* File Operations /proc */
struct proc_ops proc_fops = {
  .proc_ioctl = my_ioctl
};

module_init(kss_module_init);
module_exit(kss_module_exit);


/*IMPLEMENTATION*/
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

    dprint_info("%s: [MODULE INIT] [%d] The address of the table IDT is  %px\n",MOD_NAME, current->pid, (void *)idt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    /* Recovery the memory address of the Kallsyms_lookup_name () function */
    kallsyms_lookup_name = get_kallsyms_lookup_name();
    if(kallsyms_lookup_name == NULL) {
        pr_err("%s: [ERROR MODULE INIT] [%d] Error in recovering function kallsyms_lookup_name()\n", MOD_NAME, current->pid);
        return -1;
    }

    dprint_info("%s: [MODULE INIT] [%d] The function kallsyms_lookup_name() It is present at the memory address %px\n",
            MOD_NAME, current->pid,
            (void *)kallsyms_lookup_name);
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
    sysvec_spurious_apic_interrupt = (sysvec_spurious_apic_interrupt_t)sysvec_spurious_apic_interrupt_addr;

    dprint_info("%s: [MODULE INIT] [SPURIOUS] [%d] asm_sysvec_spurious_apic_interrupt --> %px\t"
            "sysvec_spurious_apic_interrupt --> %px\n",
            MOD_NAME, current->pid,
            (void *)asm_sysvec_spurious_apic_interrupt_addr,
            (void *)sysvec_spurious_apic_interrupt_addr);

    /* Recovery the address of the actual ASM manager in the descriptor of the IDT */
    addr_spurious_first_handler = get_full_offset_spurious_interrput(idt);

    dprint_info("%s: [MODULE INIT] [SPURIOUS] [%d] Effective Handler Asm is located at the address %px\n",
            MOD_NAME, current->pid,
            (void *)addr_spurious_first_handler);
    
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

    dprint_info("%s: [MODULE INIT] [INVALID OPCODE] [%d] asm_exc_invalid_op --> %px\t"
            "exc_invalid_op --> %px\n",
            MOD_NAME, current->pid,
            (void *)asm_exc_invalid_op_addr,
            (void *)exc_invalid_op_addr);
    
    /* Recovery the virtual address of the manager asm #6 effective */
    addr_invalid_op_first_handler = get_full_offset_invalid_opcode(idt); 

    dprint_info("%s: [MODULE INIT] [INVALID OPCODE] [%d] The actual Handler Asm is located at the address %px\n",
            MOD_NAME, current->pid,
            (void *)addr_invalid_op_first_handler);

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


    //if definined the loggig system
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
    
    //TODO continuare a copiare 


#endif



}

void kss_module_exit(void) {

}


static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

}