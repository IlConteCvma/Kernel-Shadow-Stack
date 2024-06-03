#ifndef KSS_LOADER_H
#define KSS_LOADER_H


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
#if defined(IOCTL_INSTRUM_MAP) || defined(RANDOM_SUBSET_FUNC)
    char *path_instr_info;
#endif
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

#endif