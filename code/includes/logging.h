#ifndef LOGGING_H
#define LOGGING_H

#include <linux/workqueue.h>
#include "kss_struct.h"
//#include "module-defines.h"


#ifdef LOG_SYSTEM
/* Workqueue name */
extern const char *workqueue_name;

/* Workqueue for the asynchronous writing of events and the portion of corrupt user stack on log files */
extern struct workqueue_struct *wq;
#endif



/**
 * Param_kWorker - represents the parameters that will have to have passed to the Kworker Daemon for writing
 * Of the events/of the portion of corrupt user stack inside the log file associated with the thread.
 *
 * @type: serves to understand if you have to write a buffer of events or the portion of corrupt user stack
 * @user_stack: Puntor to the portion of the corrupt user stack
 * @user_stack_size: size of the portion of corrupt user stack
 * @id_user: user identification passed to the Loader Elf to identify the new process
 * @program_name: name of the program of which the new process is
 * @tid: identification of the thread to which the information to be reported on files is associated
 * @buffer_log: Buffer containing the Log events
 * @The_Work: 'Work_Struct' data structure
 */
typedef struct param_kworker {
    int type;
    unsigned long *user_stack;
    size_t user_stack_size;
    int id_user;
    char *program_name;
    int tid;
    unsigned char *buffer_log;
    struct work_struct the_work;
} param_kworker;




// Functions
extern void flush_buffer_log(unsigned long data);
extern int save_user_stack(unsigned long start_address, security_metadata *sm);
extern int init_buffer_log(security_metadata *sm);
extern int buffer_log_switch(security_metadata *sm);
extern int write_suc_event_to_log_buffer(unsigned long ret_addr_kernel, 
                unsigned long ret_addr_user, unsigned long ret_instr_addr, security_metadata *sm);
extern int write_ret_event_to_log_buffer(unsigned long ret_instr_addr, unsigned long return_address, 
                security_metadata *sm, bool is_ii);
extern int write_call_event_to_log_buffer(unsigned long target_func_addr, unsigned long return_address, security_metadata *sm);
extern int write_no_call_event_to_log_buffer(unsigned long ret_instr_addr, unsigned long return_address, security_metadata *sm);



#endif //LOGGING_H