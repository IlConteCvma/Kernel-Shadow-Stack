#ifndef DEFINES_H
#define DEFINES_H

//TODO completare

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


#endif