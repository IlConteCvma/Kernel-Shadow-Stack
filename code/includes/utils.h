
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

//----- FILE UTILS

#ifdef LOG_SYSTEM