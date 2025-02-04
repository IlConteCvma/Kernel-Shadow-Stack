#ifndef KSS_LOADER_H
#define KSS_LOADER_H

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


/*
 * instrum_param - Contains the parameters that must be used to perform the teenage of the program.
 *
 * @data: base of the Memory View of the Elf file
 * @new_mapp_aarea: base of the new map of the mapped memory containing the information to simulate the calls
 * @et_dyn: type of the ELF file (ET_DYN or ET_EXEC)
 * @num_istr_call: number of calls to be made up
 * @num_istr_ret: Ret number to be made up
 * @path_instr_info: director of the directory containing the instrument information
 * @input_file: absolute path of the new file to be loaded
 * @id_user: User -numerical identification used to create log files
 */
typedef struct instrum_param {
    unsigned char * data;
    struct instru_call_info *new_mapp_area;
    int et_dyn;
    int num_istr_call;
    int num_istr_ret;
    char *path_instr_info;
#ifdef LOG_SYSTEM
    char *input_file;
    int id_user;
#endif
#ifdef RANDOM_SUBSET_FUNC
#ifdef RAND_PERC
    int perc;
#endif
#endif
} instrum_param;

/**
 * info_seg - Keeps information for a single segment of the ELF executable.
 *
 * @Dest: base of the memory segment
 * @size: size of the memory segment
 * @prot: Protections of the memory segment defined in the ELF executable
 * @next: pointer to the next element in the list
 */
typedef struct info_seg {
    ElfW(Addr) dest;
    size_t size;
    int prot;
    struct info_seg *next;
} info_seg;


/*
 * instru_call_info - Contains the information that must be written for each call education from
 * Instrument in the new memory area.Call information is as follows:
 * 1. INDUCATION INDERS TO CAKE AN SPURE SCURPT in order to simulate a call.
 * 2. Three two -byte Nop instructions to align the stack.
 * 3. Absolute address of the target function to which the kernel will pass control.
 * 4. Return Address to be placed both on the new Kernel Stack and on the user.
 */
struct instru_call_info {
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
    unsigned char byte5;
    unsigned char byte6;
    unsigned char byte7;
    unsigned char byte8;
    unsigned long abs_address_func;
    unsigned long ret_addr;
};

#ifdef RANDOM_SUBSET_FUNC
/**
 * random_index - Numerical index generated randomly of a function to be made.
 *
 * @idx: numerical index of the function
 * @next: pointer to the next index on the connected list
 */
typedef struct random_index {
    unsigned long idx;
    struct random_index *next;
} random_index;
#endif //RANDOM_SUBSET_FUNC

void do_instrumentation(instrum_param* param);

#endif