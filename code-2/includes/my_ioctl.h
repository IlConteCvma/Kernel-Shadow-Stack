#ifndef INSTRUM_MAP_H
#define INSTRUM_MAP_H

#include "module-defines.h"

#ifdef IOCTL_INSTRUM_MAP
#include <linux/types.h>
#define INSTRUM_MAP _IOW('a', 'a', struct ioctl_data *)
/**
 * ioctl_data - Contains information that will be communicated to the Linux Kernel via the
 * ioctl of node in /proc. Allow construction of layer instrumentation map
 * kernel to validate simulation requests.
 *
 * @call_num  : Number of instrumented calls
 * @ret_num   : Number of instrumented RET
 * @call_array: Virtual memory address array of instrumented CALLS
 * @ret_array : Instrumented RET virtual memory address array
 * @start_text: Start of the . text section that has been instrumented
 * @end_text  : End of . text section that has been instrumented
 */
struct ioctl_data {
    int call_num;
    int ret_num;
    unsigned long *call_array;
    unsigned long *ret_array;
    unsigned long start_text;
    unsigned long end_text;
};

#endif //IOCTL_INSTRUM_MAP

#ifdef LOG_SYSTEM
/**
 * Log_System_info - The information necessary to perform a correct monitoring:
 * To generate readable events and to build the name of the associated log file
 * at the thread running.
 *
 * @memory_mapped_base: baseOfLoadingTheNewProgram
 * @id_User: User identification associated with the new program to be launched
 * @program_name: name of the executable of which the new process is
 * @len: name length
 */
typedef struct log_system_info {
    unsigned long memory_mapped_base;
    int id_user;
    char *program_name;
    size_t len;
} log_system_info;



#define SECURITY_METADATA _IOW('b', 'b', log_system_info *)
#else
#define SECURITY_METADATA _IO('b', 'b')
#endif 




#endif //INSTRUM_MAP_H