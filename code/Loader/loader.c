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
void load_and_exec(unsigned char *elf, char **argv, char **env, size_t *stack) {
    int fd;
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
    // Map elf to mem
    map(elf, &exe);
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

        map(data, &interp);
        munmap(data, statbuf.st_size);
        if (interp.ehdr == MAP_FAILED) {
            dprint("Unable to map interpreter for ELF file: %s\n", strerror(errno));
            abort();
        }
        dprint("Mapped ELF interp file in: %s\n", exe.interp);
    } else {
        interp = exe;
    }
    // Count argc
    for (argc = 0; argv[argc]; argc++)
        ;

    dprint("Arguments passed: %zu\n", argc);
    stack_setup(stack, argc, argv, env, NULL,  // AUXV NULL = create syntethic AUXV
                exe.ehdr, interp.ehdr);

    dprint("Jumping to: 0x%08zx\n", interp.entry_point);
    jump(interp.entry_point, stack);
}

