#include "includes/utils.h"

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