#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <reflect.h>

int main(int argc, char **argv)
{
	int fd;
#ifdef LOG_SYSTEM
    int id_user;
#endif
	struct stat statbuf;
	unsigned char *data = NULL;

    /*
     * Il processo Loader ELF prende i seguenti parametri:
     * 0. 'reflect'        : rappresenta il nome del Loader ELF eseguibile che è stato lanciato.
     * 1. 'path_instr_info': rappresenta il percorso assoluto della directory contenente le informazioni necessarie per
     *                       instrumentare l'eseguibile che verrà caricato dal Loader ELF.
     * 2. 'id_user'        : rappresenta un identificativo numerico che viene passato solamente se è stato attivato il
     *                       monitoraggio del nuovo processo. E' un'identificativo con cui verranno creati i file di LOG
     *                       associati al nuovo processo e consentirà di avere differenti processi che sono istanze di una
     *                       stessa applicazione.
     * 3. 'perc'           : percentuale delle funzioni disponibili che dovranno essere instrumentate in modo randomico
     * 4. 'input_file      : rappresenta il percorso assoluto del file che dovrà essere caricato dal Loader ELF.
     */

#ifdef LOG_SYSTEM

#ifdef RAND_PERC
	if(argc < 5) {
		printf("[ERRORE MAIN] reflect path_instr_info id_user perc input_file [arg input_file]\n");
		return 1;
	}
#else
	if(argc < 4) {
		printf("[ERRORE MAIN] reflect path_instr_info id_user input_file [arg input_file]\n");
		return 1;
	}
#endif //RAND_PERC

    /* Faccio un controllo di correttezza sull'identificativo numero utente         */
    id_user = atoi(argv[2]);

    if(id_user <= 0) {
        printf("[ERRORE MAIN] L'identificativo numerico utente deve essere strettamente maggiore di zero\n");
        return 1;
    }

#else //LOG_SYSTEM

#ifdef RAND_PERC
	if(argc < 4) {
		printf("[ERRORE MAIN] reflect path_instr_info perc input_file [arg input_file]\n");
		return 1;
	}
#else
	if(argc < 3) {
		printf("[ERRORE MAIN] reflect path_instr_info input_file [arg input_file]\n");
		return 1;
	}
#endif //RAND_PERC

#endif //LOG_SYSTEM
    
    /* Apertura del nuovo file che dovrà essere caricato e lanciato dal Loader ELF  */


#ifdef LOG_SYSTEM

#ifdef RAND_PERC
    fd = open(argv[4], O_RDONLY);

    if(fd == -1) {
		printf("[ERRORE MAIN] Errore nell'apertura del file %s: %s\n", argv[4], strerror(errno));
		return 1;
	}
#else
    fd = open(argv[3], O_RDONLY);

    if(fd == -1) {
		printf("[ERRORE MAIN] Errore nell'apertura del file %s: %s\n", argv[3], strerror(errno));
		return 1;
	}
#endif //RAND_PERC

#else

#ifdef RAND_PERC
    fd = open(argv[3], O_RDONLY);

    if(fd == -1) {
		printf("[ERRORE MAIN] Errore nell'apertura del file %s: %s\n", argv[3], strerror(errno));
		return 1;
	}
#else
    fd = open(argv[2], O_RDONLY);

    if(fd == -1) {
		printf("[ERRORE MAIN] Errore nell'apertura del file %s: %s\n", argv[2], strerror(errno));
		return 1;
	}
#endif //RAND_PERC

#endif //LOG_SYSTEM 

    /* Recupero le informazioni relative al nuovo file da lanciare */
	if(fstat(fd, &statbuf) == -1) {
		printf("[ERRORE MAIN] Errore nel recupero delle informazioni dal file: %s\n", strerror(errno));
		return 1;
	}

    /* Mappo il nuovo file nella memoria. Nel buffer puntato da 'data' abbiamo la DISK VIEW del file    */
	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if(data == MAP_FAILED) {
		printf("[ERRORE MAIN] Errore nel memory mapping della DISK VIEW del file: %s\n", strerror(errno));
		return 1;
	}

	close(fd);

    /* Rimuovo il nome del Loader ELF dagli argomenti che dovranno essere passati al nuovo processo     */
	reflect_execves(data, argv + 1, NULL, (size_t *) argv - 1);

	return 0;
}
