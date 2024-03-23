
#ifndef UTILS_H
#define UTILS_H

#include <linux/fs.h>

/* Allows you to reconstruct the address of the ASM manager stored in the entry of the IDT table                        */
#define HML_TO_ADDR(h,m,l)      ((unsigned long) (l) | ((unsigned long) (m) << 16) | ((unsigned long) (h) << 32))

/* The offset avoids the overwriting of the possible thread_info structure in the original Stack Kernel                 */
#ifdef CONFIG_THREAD_INFO_IN_TASK
int offset_thread_info = sizeof(struct thread_info);
#else
int offset_thread_info = 0; 
#endif

/* Get the base of the original current thread stack kernel                                                    */
#define GET_KERNEL_STACK_BASE(p) p = (unsigned long *)((void*)current->stack + offset_thread_info);

/* Get the pointer to the safety metadata stored on the original kernel stack                             */
#define GET_SECURITY_METADATA(end_of_stack, sm) sm = (security_metadata *)end_of_stack[1];

extern char *get_absolute_pathname(char *buf);

//----- FILE UTILS
extern struct file *init_log(char *filename);
extern void close_log(struct file *file);


#endif //UTILS_H