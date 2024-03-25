#ifndef DEFINES_H
#define DEFINES_H

/* configuration defines ---------*/
#define DEBUG_HOOK                  //show debug msg
#define DEBUG_IOCTL_FUNC            //show debug msg for ioctl
#define DEBUG_CHECK_RETURN_ADDRESS  //
#define DEBUG_PERFORMANCE_WEAK      //
#define IOCTL_INSTRUM_MAP           // 
#define LOG_SYSTEM                  //
#define MIX_ADDRESS                 //
#define SHOW_STACK_KERNEL           //
#define CHECK_BUFFER_SIZE           //

// address control
//#define SINGLE_ADDRESS_ONE_COPY_FROM_USER
//#define MIX_ADDRESS               //
//#define BLOCK_ADDRESS               //
#define MIX_ADDRESS

//timer
#define SINGLE_ADDRESS_TIMER        //
#define TIMER_COMPARE_RET_ADDR      //
#define BLOCK_ADDRESS_TIMER         //

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
#define log_path_format  "/home/cap/%s_%d_%d_log.txt";
#define user_stack_path_format  "/home/cap/%s_%d_%d_user_stack.data";

/* List of strings containing the event format for the various types of events supported by architecture     */
#define no_call_format  "[NO CALL] :Indirizzo RETURN = 0x%px\tIndirizzo di ritorno = 0x%px\n";
#define call_format     "[CALL]    :Funzione Target  = 0x%px\tIndirizzo di ritorno = 0x%px\n";
#define ret_ii_format   "[RET II]  :Indirizzo RETURN = 0x%px\tIndirizzo di ritorno = 0x%px\n";
#define ret_ni_format   "[RET NI]  :Indirizzo RETURN = 0x%px\tIndirizzo di ritorno = 0x%px\n";
#define ret_suc_format  "[RET SUC] :Indirizzo ATTESO = 0x%px\tIndirizzo EFFETTIVO  = 0x%px\tIndirizzo RETURN = 0x%px\n";

/* Dimensions of the strings to write in the log file after recovering the event data                     */
int size_no_suc = 92 + 12;
int size_suc    = 130 + 12;
#endif //LOG_SYSTEM







#endif //DEFINES_H