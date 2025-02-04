#ifndef HOOKS_H
#define HOOKS_H


/* Names of the kernel functions on which to install the Hooks                                                               */
#define do_exit_func                 "do_exit"
#define kallsyms_lookup_name_func    "kallsyms_lookup_name"
#define finish_task_switch_func      "finish_task_switch.isra.0"
#define finish_task_switch_cold_func "finish_task_switch.isra.0.cold"
#define kernel_clone_func            "kernel_clone"


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)


/* I define the signature for the Kallsyms_lookup_name function                  */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
#endif

/**
 * @old_call_operand: operating the call to restore the disassembly of the form
 * @new_call_operand: new by operating the call to reach the new manager C
 * @call_operand_address: address of the exposure of the call
 * @old_entry: old entry of the IDT to be restored to disassembling the form
 * @my_Trap_desc: New Entry of the IDT with a minimum privilege level for access equal to 3
 */
struct info_patch {
    int old_call_operand;
    int new_call_operand;
    unsigned int *call_operand_address;
    gate_desc old_entry;
    gate_desc my_trap_desc;
};


/*FUNCTION DECLARATION*/
extern int install_kprobes(void);
extern void remove_probes(void);

extern int handler_finish_task_switch(struct kprobe *pk, struct pt_regs *regs);
extern int hook_do_exit(struct kprobe *p, struct pt_regs *regs);
extern int handler_kernel_clone(struct kprobe *p, struct pt_regs *regs);
extern kallsyms_lookup_name_t get_kallsyms_lookup_name(void);
extern void my_invalid_op_handler(struct pt_regs *regs);
extern void my_spurious_handler(struct pt_regs *regs);
extern int patch_IDT(unsigned long address_first_handler, unsigned long address_expected_C_handler, 
        struct desc_ptr dtr, int vector_number, void *handler, struct info_patch *item);

#endif