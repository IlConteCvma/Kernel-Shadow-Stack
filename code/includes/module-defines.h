#ifndef DEFINES_H
#define DEFINES_H

/* configuration defines ---------*/
#define DEBUG_HOOK                  //show debug msg
#define DEBUG_IOCTL_FUNC            //show debug msg for ioctl
#define DEBUG_CHECK_RETURN_ADDRESS  //
#define DEBUG_PERFORMANCE_WEAK      //
#define DEBUG_INVALID_OP            //
#define DEBUG_SPURIOUS              //
#define INFO_DEBUG                  //

#define IOCTL_INSTRUM_MAP           // 
#define LOG_SYSTEM                  //
#define SHOW_STACK_KERNEL           //
//#define CHECK_BUFFER_SIZE           //

//#define KILL_PROCESS_NO_CALL        //kill process if no call event


// address control
//#define SINGLE_ADDRESS_ONE_COPY_FROM_USER
//#define MIX_ADDRESS               //
//#define BLOCK_ADDRESS               //
#define MIX_ADDRESS

//timer
//#define SINGLE_ADDRESS_TIMER        //
//#define TIMER_COMPARE_RET_ADDR      //
//#define BLOCK_ADDRESS_TIMER         //

/*--------------------------------*/


/* Name of the kernel module                                                                                              */
#define MOD_NAME "KSS"

/* Block order from the Buddy System                                                                                   */
#define ORDER 4

/* Period for the disassembly of the form                                                                                 */
#define PERIOD 1

/* Log buffer size for events                                                                         */
#define BUFFER_DIM (PAGE_SIZE << ORDER)

/* Allows you to print the performance of the copy_fromer () only for a specific number of copied bytes        */
#ifdef CHECK_BUFFER_SIZE
#define BUFFER_SIZE 120
#endif

/* Threshold for the average size of the peak stacks of the pending functions                                          */
#define S 1000000
/*Number of bytes that are copied with a single copy_from_user () in mixed mode                            */
#define N 100
/* Maximum length of the name of the executable of which the current process is an application                                     */
#define MAX_PATH_EXEC 256
/* Size of the new kernel stack containing the addresses for the integrity control of the user stack         */
#define STACK_SIZE_ARCH 10000
/* REG Field for the 0xff calls of the Byte that extends the operating code                                                */
#define IS_FF_REG 0X38
/* Magic Number To check the status of the original and safety metadata stack kernel                       */
#define MAGIC_NUMBER 0x0123456789ABCDEF


#ifdef LOG_SYSTEM
/* The location in the System file and the format of log files produced by the monitoring system                       */
#define log_path_format  "/home/cap/%s_%d_%d_log.txt"
#define user_stack_path_format  "/home/cap/%s_%d_%d_user_stack.data"

/* List of strings containing the event format for the various types of events supported by architecture     */
#define no_call_format  "[NO CALL] :Address RETURN = 0x%px\tAddress di ritorno = 0x%px\n"
#define call_format     "[CALL]    :Function Target  = 0x%px\tAddress di ritorno = 0x%px\n"
#define ret_ii_format   "[RET II]  :Address RETURN = 0x%px\tAddress di ritorno = 0x%px\n"
#define ret_ni_format   "[RET NI]  :Address RETURN = 0x%px\tAddress di ritorno = 0x%px\n"
#define ret_suc_format  "[RET SUC] :Address ATTESO = 0x%px\tAddress EFFETTIVO  = 0x%px\tAddress RETURN = 0x%px\n"

/* Dimensions of the strings to write in the log file after recovering the event data                     */
extern int size_no_suc ; //in driver-core.c
extern int size_suc    ; //in driver-core.c
#endif //LOG_SYSTEM




typedef void (*do_group_exit_t)(int code);

extern do_group_exit_t do_group_exit_addr; //in driver-core.c








#endif //DEFINES_H