#include "include/include.h"


int main(int argc, char **argv) {
    /*
* The Loader Elf process takes the following parameters:
* 0. 'Kss_loader': represents the name of the ELF Loader executable that has been launched.
* 1. 'Path_instr_info': represents the absolute path of the directory containing the information necessary for
* Instrument the executable that will be loaded by the Loader Elf.
* 2. 'Id_user': represents a numerical identification that is passed only if the
* monitoring of the new process. It is an identification with which log files will be created
* associated with the new process and will allow you to have different processes that are instances of one
* Same application.
* 3. 'Because: percentage of the available functions that must be made in a random way
* 4. 'Input_file: represents the absolute path of the file that will have to be loaded by the Loader Elf.
*/

    int fd;
#ifdef LOG_SYSTEM
    int id_user;
#endif
	struct stat statbuf;
	unsigned char *elf = NULL;

    int max_argc;

#ifdef LOG_SYSTEM
    #ifdef RAND_PERC
        max_argc = 5;
        #define ERRORUSAGE_STR "[ERROR MAIN] Kss_loader path_instr_info id_user perc input_file [arg input_file]\n"
    #else
        max_argc = 4;
        #define ERRORUSAGE_STR "[ERROR MAIN] Kss_loader path_instr_info id_user input_file [arg input_file]\n"
    #endif
#else //LOG_SYSTEM
    #ifdef RAND_PERC
        max_argc = 4;
        #define ERRORUSAGE_STR "[ERROR MAIN] Kss_loader path_instr_info perc input_file [arg input_file]\n"
    #else
        max_argc = 3;
        #define ERRORUSAGE_STR "[ERROR MAIN] Kss_loader path_instr_info input_file [arg input_file]\n"
    #endif
#endif

    // Control correct number passed
    // TODO not complete control on user type passed 
    if (argc < max_argc)
    {
        printf(ERRORUSAGE_STR);
        return 1;
    }

#ifdef LOG_SYSTEM
    /* I make a correctness check on the user number identification        */
    // always passed as second argument in argv
    id_user = atoi(argv[2]);

    if(id_user <= 0) {
        printf("[ERROR MAIN] The user's numeric identification must be strictly greater than zero\n");
        return 1;
    }

#endif //LOG_SYSTEM

    /* Opening of the new file that must be uploaded and launched by the Loader Elf  */
    // last element passed in argv

    fd = open(argv[max_argc-1], O_RDONLY);
    if(fd == -1) {
        printf("[ERROR MAIN] Error in opening the file %s: %s\n", argv[max_argc-1], strerror(errno));
        return 1;
    }

    /* Recovery of information relating to the new file to be launched */
	if(fstat(fd, &statbuf) == -1) {
		printf("[ERROR MAIN] Error in recovering information from the file: %s\n", strerror(errno));
		return 1;
	}

    /* Mapping the new file in the memory. In the buffer 'elf' we have the disk view of the file    */
	elf = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if(elf == MAP_FAILED) {
		printf("[ERROR MAIN] Memory mapping error of the DISK View of the file: %s\n", strerror(errno));
		return 1;
	}

	close(fd);

    /* Remove extra argv*/
    load_and_exec(elf, argv + 1, NULL, (size_t *)argv - 1);

    return 0;
}