#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <reflect.h>

#include "reflect_common.h"

extern char **environ;

/**
 * reflect_execves - Costruzione della MEMORY VIEW del nuovo programma e del suo eventuale interprete. Viene eseguito il
 * setup dello stack per il nuovo programma e si salta all'entry point del nuovo programma.
 *
 * @elf  : Puntatore alla DISK VIEW del nuovo file da eseguire
 * @argv : Puntatore agli argomenti
 * @env  : Puntatore alle variabili di ambiente
 * @stack: Puntatore allo stack
 */
void reflect_execves(const unsigned char *elf, char **argv, char **env, size_t *stack) {
	int fd;
#ifdef LOG_SYSTEM
    int id_user;
#endif
#ifdef RAND_PERC
    int perc;
#endif
    size_t argc;
	struct stat statbuf;
	unsigned char *data = NULL;
	struct mapped_elf exe = {0}, interp = {0};


    /* Verifico se il formato ELF del nuovo file da lanciare è corretto */
	if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
        printf("[ERRORE REFLECT EXECVES] Il formato ELF del nuovo file non sembra essere corretto...\n");
		abort();
	}

    /* Setto le variabili di ambiente */
	if (env == NULL) {
		env = environ;
	}

#ifdef LOG_SYSTEM
    /* Recupero l'identificativo numerico utente che verrà utilizzato dal Kernel per creare i file di LOG */
    id_user = atoi(argv[1]);

    if(id_user == 0) {
        printf("[ERRORE REFLECT EXECVES] Errore nel recupero dell'identificativo numerico utente: il valore 0 non è ammesso\n");
        exit(EXIT_FAILURE);
    }

#ifdef RAND_PERC
    perc = atoi(argv[2]);

    if(perc == 0 || perc < 0 || perc > 100) {
        printf("[ERRORE REFLECT EXECVES] Errore della percentuale di funzioni da instrumentare randomicamente: %d\n", perc);
        exit(EXIT_FAILURE);
    }
#endif //RAND_PERC

    printf("[REFLECT EXECVES] Il percorso della directory contenente le informazioni di instrumentazione è %s\n", argv[0]);
    printf("[REFLECT EXECVES] L'identificativo numerico utente che verrà associato al nuovo processo è %d\n", id_user);
#ifdef RAND_PERC
    printf("[REFLECT EXECVES] La percentuale di funzioni da instrumentare randomicamente è %d\n", perc);
#endif //RAND_PERC


#ifdef RAND_PERC
    printf("[REFLECT EXECVES] Il percorso del nuovo file ELF da lanciare è %s\n", argv[3]);

    /* Costruisco la MEMORY VIEW per il nuovo programma caricando i segmenti in memoria */
	map_elf(elf, &exe, 0, argv[0], argv[3], id_user, perc);
#else
    printf("[REFLECT EXECVES] Il percorso del nuovo file ELF da lanciare è %s\n", argv[2]);

    /* Costruisco la MEMORY VIEW per il nuovo programma caricando i segmenti in memoria */
	map_elf(elf, &exe, 0, argv[0], argv[2], id_user);
#endif //RAND_PERC

#else //LOG_SYSTEM

    printf("[REFLECT EXECVES] Il percorso della directory contenente le informazioni di instrumentazione è %s\n", argv[0]);

#ifdef RAND_PERC
    perc = atoi(argv[1]);

    if(perc == 0 || perc < 0 || perc > 100) {
        printf("[ERRORE REFLECT EXECVES] Errore della percentuale di funzioni da instrumentare randomicamente: %d\n", perc);
        exit(EXIT_FAILURE);
    }
#endif //RAND_PERC
    

#ifdef RAND_PERC
    printf("[REFLECT EXECVES] Il percorso del nuovo file ELF da lanciare è %s\n", argv[2]);
    map_elf(elf, &exe, 0, argv[0], perc);
#else
    printf("[REFLECT EXECVES] Il percorso del nuovo file ELF da lanciare è %s\n", argv[1]);
    map_elf(elf, &exe, 0, argv[0]);
#endif //RAND_PERC

#endif

	if (exe.ehdr == MAP_FAILED) {
		dprint("Unable to map ELF file: %s\n", strerror(errno));
		abort();
	}

	if (exe.interp) {
		// Load input ELF executable into memory
		fd = open(exe.interp, O_RDONLY);
		if(fd == -1) {
			dprint("Failed to open %p: %s\n", exe.interp, strerror(errno));
			abort();
		}

		if(fstat(fd, &statbuf) == -1) {
			dprint("Failed to fstat(fd): %s\n", strerror(errno));
			abort();
		}

		data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if(data == MAP_FAILED) {
			dprint("Unable to read ELF file in: %s\n", strerror(errno));
			abort();
		}
		close(fd);

#ifdef LOG_SYSTEM

#ifdef RAND_PERC
        map_elf(data, &interp, 1, NULL, NULL, -1, -1);
#else
        map_elf(data, &interp, 1, NULL, NULL, -1);
#endif //RAND_PERC

#else //LOG_SYSTEM

#ifdef RAND_PERC
        map_elf(data, &interp, 1, NULL, -1);
#else
		map_elf(data, &interp, 1, NULL);
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

/***********************************************************/

/* Rimuovo i parametri aggiuntivi del Loader in modo da lanciare correttamente il nuovo programma */
#ifdef LOG_SYSTEM

#ifdef RAND_PERC
    /* Rimuovo il percorso della directory contenente le informazioni sulla instrumentazione e sul monitoraggio e la percentuale */
    argv = argv + 3;
#else
    /* Rimuovo il percorso della directory contenente le informazioni sulla instrumentazione e sul monitoraggio */
    argv = argv + 2;
#endif //RAND_PERC

#else //LOG_SYSTEM

#ifdef RAND_PERC
    /* Rimuovo il percorso della directory contenente le informazioni sulla instrumentazione e la percentuale */
    argv = argv + 2;
#else
    /* Rimuovo il percorso della directory contenente le informazioni sulla instrumentazione */
    argv = argv + 1;
#endif //RAND_PERC

#endif //LOG_SYSTEM


/***********************************************************/

	for (argc = 0; argv[argc]; argc++);

    printf("Entry point del mio programma: %p\n", (void *)exe.entry_point);    
    fflush(stdout);

	stack_setup(stack, argc, argv, env, NULL,
			exe.ehdr, interp.ehdr);

	jump_with_stack(interp.entry_point, stack);
}
