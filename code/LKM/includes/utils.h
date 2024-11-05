#ifndef UTILS_H
#define UTILS_H

#include <linux/fs.h>

/*DEBUG PRINT FUNCTIONS*/
#ifdef DEBUG_TEST
#define DEBUG
#endif

#ifdef DEBUG_V
#define DEBUG
#endif

#ifdef DEBUG_LOG
#define DEBUG
#endif

#ifdef DEBUG_HOOK
#define DEBUG
#endif



#ifdef DEBUG

//info function
#define dprint_info(...) (pr_info(__VA_ARGS__))

// more verbose function
#ifdef DEBUG_TEST
#define dprint_info_test(...) (pr_info(__VA_ARGS__))
#else
#define dprint_info_test(...)
#endif

//verbose level
#ifdef DEBUG_V
#define dprint_info_v(...) (pr_info(__VA_ARGS__))
#else
#define dprint_info_v(...)
#endif

#ifdef DEBUG_LOG
#define dprint_info_log(...) (pr_info(__VA_ARGS__))
#else
#define dprint_info_log(...)
#endif

#ifdef DEBUG_HOOK
#define dprint_info_hook(...) (pr_info(__VA_ARGS__))
#else
#define dprint_info_hook(...)
#endif

#else
#define dprint_info(...)
#define dprint_info_test(...)
#define dprint_info_v(...) 
#define dprint_info_log(...)
#define dprint_info_hook(...)
#endif



/* Allows you to reconstruct the address of the ASM manager stored in the entry of the IDT table                        */
#define HML_TO_ADDR(h,m,l)      ((unsigned long) (l) | ((unsigned long) (m) << 16) | ((unsigned long) (h) << 32))
/* The offset avoids the overwriting of the possible thread_info structure in the original Stack Kernel                 */
#ifdef CONFIG_THREAD_INFO_IN_TASK
extern int offset_thread_info ;
#else
extern int offset_thread_info ; 
#endif

/* Get the base of the original current thread stack kernel                                                    */
#define GET_KERNEL_STACK_BASE(p) p = (unsigned long *)((void*)current->stack + offset_thread_info);

extern unsigned long cr0;
static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;

    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) {
    write_cr0_forced(cr0);
}

static inline void unprotect_memory(void) {
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}

//----- Functions
extern char *get_absolute_pathname(char *buf);


extern struct file *init_log(char *filename);
extern void close_log(struct file *file);
extern void kill_process(void);
extern int is_FF_call(unsigned char *instr_addr);
extern int is_E8_call(unsigned char *instr_addr);
extern int check_call_security(unsigned char *ret_addr_user);

extern unsigned long get_full_offset_by_vector(gate_desc *idt, int vector_number);
extern unsigned long get_full_offset_spurious_interrput(gate_desc *idt);
extern unsigned long get_full_offset_invalid_opcode(gate_desc *idt);


#endif