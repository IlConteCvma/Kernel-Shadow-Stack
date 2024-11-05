#include "include/include.h"



extern char **environ;


/**
 * load_and_exec - Construction of the memory view of the new program and its possible interpreter.The
 * Stack setup for the new program and jump to the entry point of the new program.
 *
 * @elf  : Pointer at the disk view of the new file to be made
 * @argv : Pointer to the args
 * @env  : Pointer to the environment variables
 * @stack: Pointer at the stack
 */
/*[ERROR MAIN] path_instr_info id_user perc input_file [arg input_file]*/

void load_and_exec(unsigned char *elf, char **argv, char **env, size_t *stack) {
    int fd;
#ifdef LOG_SYSTEM
    int id_user;
#endif
#ifdef RAND_PERC
    int perc;
#endif 
    struct stat statbuf;
    unsigned char *data = NULL;
    size_t argc;

    struct elf_info exe = {0}, interp = {0};

    if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
        dprint("ELF file not compatible. Abort!\n");
        abort();
    }

    if (env == NULL) {
        env = environ;
    }

    /*Retrive kss instrumentation variable*/
#ifdef LOG_SYSTEM

    id_user = atoi(argv[1]);
    if(id_user == 0) {
        printf("[ERROR REFLECT EXECVES] Error in the recovery of the user identification of user: value 0 is not allowed\n");
        exit(EXIT_FAILURE);
    }

    printf("[REFLECT EXECVES] The route of the directory containing the instrument information is %s\n", argv[0]);
    printf("[REFLECT EXECVES] The users of the user who will be associated with the new process is %d\n", id_user);

    #ifdef RAND_PERC

    perc = atoi(argv[2]);
    if(perc == 0 || perc < 0 || perc > 100) {
        printf("[ERROR REFLECT EXECVES] Percentage error of functions to be made in the instrustment randomly: %d\n", perc);
        exit(EXIT_FAILURE);
    }

    printf("[REFLECT EXECVES] The percentage of functions to be treated randomly is %d\n", perc);
    printf("[REFLECT EXECVES] The path of the new Elf file to be launched is%s\n", argv[3]);

    map(elf, &exe, 0, argv[0], argv[3], id_user, perc)
    #else
    printf("[REFLECT EXECVES] The path of the new Elf file to be launched is%s\n", argv[2]);
    map(elf, &exe, 0, argv[0], argv[2], id_user);
    #endif


#else
    printf("[REFLECT EXECVES] The route of the directory containing the instrument information is %s\n", argv[0]);
    #ifdef RAND_PERC

    perc = atoi(argv[2]);
    if(perc == 0 || perc < 0 || perc > 100) {
        printf("[ERROR REFLECT EXECVES] Percentage error of functions to be made in the instrustment randomly: %d\n", perc);
        exit(EXIT_FAILURE);
    }

    printf("[REFLECT EXECVES] The percentage of functions to be treated randomly is %d\n", perc);
    printf("[REFLECT EXECVES] The path of the new Elf file to be launched is%s\n", argv[2]);
    map(elf, &exe, 0, argv[0], perc);

    #else
    printf("[REFLECT EXECVES] The path of the new Elf file to be launched is%s\n", argv[1]);
    map(elf, &exe, 0, argv[0]);
    #endif
#endif

    if (exe.ehdr == MAP_FAILED) {
        dprint("Unable to map ELF file: %s\n", strerror(errno));
        abort();
    }

    // Load input interp Elf executable into memory
    if (exe.interp) {
        fd = open(exe.interp, O_RDONLY);
        if (fd == -1) {
            dprint("Failed to open interp file %p: %s\n", (void *)exe.interp, strerror(errno));
            abort();
        }

        if (fstat(fd, &statbuf) == -1) {
            dprint("Failed to fstat(fd): %s\n", strerror(errno));
            abort();
        }

        data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) {
            dprint("Unable to read interp ELF file in: %s\n", strerror(errno));
            abort();
        }
        close(fd);

        //mapping interpeter
#ifdef LOG_SYSTEM

    #ifdef RAND_PERC
            map(data, &interp, 1, NULL, NULL, -1, -1);
    #else
            map(data, &interp, 1, NULL, NULL, -1);
    #endif //RAND_PERC

#else //LOG_SYSTEM

    #ifdef RAND_PERC
            map(data, &interp, 1, NULL, -1);
    #else
            map(data, &interp, 1, NULL);
    #endif //RAND_PERC

#endif //LOG_SYSTEM

        munmap(data, statbuf.st_size);
        if (interp.ehdr == MAP_FAILED) {
            dprint("Unable to map interpreter for ELF file: %s\n", strerror(errno));
            abort();
        }
        dprint("Mapped ELF interp file in: %s\n", exe.interp);
    } else {
        interp = exe;
    }

    
#ifdef LOG_SYSTEM
    #ifdef RAND_PERC
        argv = argv + 3;
    #else
        argv = argv + 2;
    #endif 
#else 
    #ifdef RAND_PERC
        argv = argv + 2;
    #else
        argv = argv + 1;
    #endif 
#endif 

    // Count argc
    for (argc = 0; argv[argc]; argc++)
        ;

    dprint("Arguments passed: %zu\n", argc);
    stack_setup(stack, argc, argv, env, NULL,  // AUXV NULL = create syntethic AUXV
                exe.ehdr, interp.ehdr);

    dprint("Jumping to: 0x%08zx\n", interp.entry_point);
    jump(interp.entry_point, stack);
}

