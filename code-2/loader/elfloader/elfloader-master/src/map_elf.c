#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <reflect.h>
#include "map_elf.h"

/* ---------------------------------------ROBA AGGIUNTA------------------------------------------------------ */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <time.h>

/* Includes for the use of the nodo in /proc/ */
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ioctl_kss.h"


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

/* List of the list of the list containing the information on the segments of the executable */
info_seg * info_seg_head = NULL;

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


/* A little useful strings for the construction of the absolute paths in the recovery of instrument information*/
const char *file_path_number_suf_call = "call/number.txt";
const char *file_path_number_suf_ret = "ret/number.txt";
const char *dir_path_call_suf = "call/";
const char *dir_path_ret_suf = "ret/";

/* Absolute path of the file containing the number of calls to be made up*/
char file_path_number_call[256] = {0};

/* Absolute route of the file containing the number of Ret to be made up */
char file_path_number_ret[256] = {0};

/* Absolute path of the directory containing the instrumentation information for the CALL */
char dir_path_call[256] = {0};

/*Absolute path of the directory containing the instrumentation information for the RET */
char dir_path_ret[256] = {0};

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

/**
 * do_instrumentation -Performs the institution of the call and ret instructions in the program
 * loaded by the Loader Elf.Possibly, communicate to the Linux kernel the instrument map for the
 * Loader Elf's current request, creates the file containing the details of the instruated memory area
 * and communicate the monitoring information to allow it to the Linux kernel to identify correctly
 * The offset of instructions and functions in the executable and to create log files.
 *
 * @param: pointer to the information necessary to perform the instrumentation.
 */
void do_instrumentation(instrum_param* param) {
    int operand;
    int num_istr_did;
    signed int new_operand;
    DIR *dir;
    FILE *file;
    struct dirent *entry;    
    char linea[256];
    char filename_instr[256];
    unsigned char * byte;
    unsigned long address;
    unsigned long offset_instr;
    int is_in;
    int id_func;
    char func_name[256];
    int fd;                                     /* fileDescriptorDelNodoIn /proc                                           */
    const char *node = "/proc/kss_node";       /* Path of the node in /proc to communicate the activities to be performed at the kernel*/
#ifdef LOG_SYSTEM
    char *last_occ;
    log_system_info lsi;
#endif
#ifdef IOCTL_INSTRUM_MAP
    struct ioctl_data *my_ioctl_data;           /* User Space Instruments Map                                       */
    unsigned long start_text;                   /* Beginning of the section .text                                                  */
    unsigned long end_text;                     /* End of the section .text                                                    */
#endif
#ifdef RANDOM_SUBSET_FUNC
    /* Pointer at the first element of the list containing the indexes of the functions to be made up randomly generated. */
    random_index *random_idx_list_head = NULL;
    random_index *curr_random_idx = NULL;
    random_index *prev = NULL;
    random_index *new_item = NULL;
    int num_func;
    int curr_idx_used;
    int *idx_used;
    bool is_used;
    int new_rand_idx;
    int rand_subset_dim;
    time_t seed;
#ifndef RAND_PERC
    int count_error;
#endif
#ifndef WITH_IN
    /* If non -type in type scenarios must be maintained the functions of the functions that do not generate them*/
    int counter_no_is_in_func = 0;
    int last_id_func=-1;
#endif
#endif //RANDOM_SUBSET_FUNC


#ifdef RANDOM_SUBSET_FUNC

    /*
     * Regardless of whether or not you consider the type in type scenarios, I want to instruct only one
     * subset of the functions considered.Therefore, a subset will be taken among all the 'good' functions
     * or only among those that do not generate type in.
     * We start by calculating the total number of functions that we can consider, depending on whether we consider
     * or not also those that generate type in.Subsequently randomly will be generated
     * Numerical indices that will correspond to the identification of the functions to be made.All this is possible
     * Since Ghidra has assigned a numerical identification to the functions.
     */

    /*I build the name of the file containing the number of functions of interest */
    strcpy(filename_instr, param->path_instr_info);

#ifdef WITH_IN

    /*We consider all the 'good' functions, even those that could lead to type scenarios in*/
    strcpy(filename_instr + strlen(filename_instr), "/num_good_func.txt");

#else

    /*We consider only those 'good' functions that do not lead to type scenarios in */
    strcpy(filename_instr + strlen(filename_instr), "/num_good_func_no_is_in.txt");

#endif //WITH_IN

    /* Reading of the number of functions that we consider for the current compilation of the Loader Elf*/

    file = fopen(filename_instr, "r");

    if(file == NULL) {
        perror("[Instruments error] [ERRORE GET FUNC SIZE] File opening error containing the number of functions to consider");
        exit(EXIT_FAILURE);
    }

    if(fscanf(file, "%d", &num_func) != 1) {
        printf("[Instruments error] [ERRORE GET FUNC SIZE] Error in reading the number of functions to consider\n");
        exit(EXIT_FAILURE);
    }

    /* I check if Ghidra has not found any function that can be instructed */
    if(num_func == 0) {
        printf("[WARNING Instrumentation] Ghidra has not found any function to be made up\n");
        goto no_rand;
    }

    /*
     * Once the number of functions is calculated, including the random choice, it is possible to determine
     * An integer value that will represent the number of functions that we will instruct.This whole value
     * can be generated in a random way or using the percentage passed to the Loader Elf via a line of
     * command.Subsequently, the numerical identifiers of the functions to be made will be generated.
     */

#ifdef RAND_PERC
    rand_subset_dim = (num_func * param->perc) / 100;

    /* I manage any case in which the final value is approved by lack of zero */
    if(rand_subset_dim == 0 && num_func > 0) {
        rand_subset_dim = 1;
    }

#else

    count_error = 0;

redo_random_number:

    /* Randomize the choice of the seed in order to have a different number of functions in the various executions*/
    seed = time(NULL);

    /* Imposed the seed generated in a 'random' way */
    srand(seed);

    /* Road randomly the number of functions that will be instructed by the Loader Elf */
    rand_subset_dim = rand() % num_func;

    if(rand_subset_dim == 0){
        if(count_error == 100) {
            rand_subset_dim = 1;
            goto out;
        }
        count_error++;
        goto redo_random_number;
    }

out:
#endif //RAND_PERC

#ifdef DEBUG_RAND_FUNC
    printf("[Instrumentation] The number of functions that will be considered is %d\n", rand_subset_dim);
#endif

    /* Alloco the array that will be used to determine if a numerical index has already been generated */
    idx_used = (int *)malloc(sizeof(int) * rand_subset_dim);

    if(idx_used == NULL) {
        perror("[error Instrumentation] ARRAGE ERROR OF ARRAY maintaining the numerical indices that have been generated:");
        exit(EXIT_FAILURE);
    }

    /* The value -1 will indicate that the position of the array is free to write a new element */
    for(int i = 0; i < rand_subset_dim; i++) {
        idx_used[i] = -1;
    }

#ifdef DEBUG_RAND_FUNC
    printf("[Instrumentation] Number of functions available:%d\tNumber of functions to be made:%d\n", num_func, rand_subset_dim);
#endif

    /*
     * The an array 'Idx_used' is used to memorize random identifiers that
     * have already been generated.In addition, this index represents the position in the Array 'IDX_USED
     * in which to write the next numerical identification to keep track of it in the generations a
     * follow.It is important to keep track of this to avoid considering the same function in the
     * Instrumentation of the program to be launched.
     */

     curr_idx_used = 0;

    /* Randomize the choice of the seed in order to have a different number of functions in the various executions */
    seed = time(NULL);

    /*Imposed the seed generated in a 'random' way */
    srand(seed);

     for(int i=0; i < rand_subset_dim; i++) {

#ifdef DEBUG_RAND_FUNC
        printf("[Instrumentation] Generation of the numerical random identification #%d/%d...\n", i + 1, rand_subset_dim);
#endif

redo:
        /* Road randomly a new numerical function identification */
        new_rand_idx = rand() % num_func;

#ifdef DEBUG_RAND_FUNC
        printf("[Instrumentation]Numeric random identification generated:%d...\n", new_rand_idx);
#endif

        /* This label allows you to check if the identification has already been generated*/
        is_used = false;

        for(int j=0; j < rand_subset_dim; j++) {

            if(idx_used[j] == -1) {
                /* I saw all the identifiers that have been generated */
                break;
            } else {
                if(idx_used[j] == new_rand_idx) {
                    is_used = true;
                    break;
                }
            }
        }

        if(is_used) goto redo;

#ifdef DEBUG_RAND_FUNC
        printf("[Instrumentation] Randomic numerical identification #%d: %d\n", i + 1, new_rand_idx);
#endif

        /* Register the numerical identification of the function that has been generated */
        idx_used[curr_idx_used] = new_rand_idx;

        curr_idx_used++;

        /*
         * allocoAndInitialTheNewElementToBeIncludedInTheListOfIdentificationIdentification *MustBeInsertedByRespectingAnOrder (strictly)GrowingAsItWillLaterProcessIt *OnTheOffsetOfTheCalls/retnOneTimeIdentificationIncludedInTheListCorrespondToThose *PresentInTheLinesOfTheInstructionFilesContainingTheOffsetsThatWereCreatedByGhidra. */

        new_item = (random_index *)malloc(sizeof(random_index));

        if(new_item == NULL) {
            perror("[Instruments error] Railing Memory Allocation error for randomic function:");
            exit(EXIT_FAILURE);
        }

        new_item->idx = new_rand_idx;
        new_item->next = NULL;

        /* Insertion respecting a strictly growing order within the connected list */

        if((random_idx_list_head == NULL) || (new_item->idx < random_idx_list_head->idx))  {

            /* Inserting the new element at the top of the list */
            new_item->next = random_idx_list_head;
            random_idx_list_head = new_item;

        } else {
                
            /* I refrain the correct position within the connected list */
            prev = random_idx_list_head;
            curr_random_idx = random_idx_list_head->next;

            while(curr_random_idx != NULL && (curr_random_idx->idx < new_item->idx) ) {
                prev = curr_random_idx;
                curr_random_idx = curr_random_idx->next;
            }

            prev->next = new_item;
            new_item->next = curr_random_idx;             
        }
    }  

#ifdef DEBUG_RAND_FUNC
    curr_random_idx = random_idx_list_head;

    printf("Printing of the list containing the random identifiers that have been generated:\n");

    while(curr_random_idx != NULL) {
        printf("%ld\n", curr_random_idx->idx);
        curr_random_idx = curr_random_idx->next;
    }
#endif //DEBUG_RAND_FUNC

no_rand:

#endif //RANDOM_SUBSET_FUNC


#ifdef IOCTL_INSTRUM_MAP
    /* I build the name of the file containing the range of the instruated memory area*/
    memset(filename_instr, 0, 256);
    strcpy(filename_instr, param->path_instr_info);
    strcpy(filename_instr + strlen(filename_instr), "/zone.txt");

    /*File opening*/
    file = fopen(filename_instr, "r");

    if(file == NULL) {
        perror("[Instruments error] [ZONE] File opening error containing the extremes of the instruated area");
        exit(EXIT_FAILURE);
    }

    /*Reading of the extremes of the instrument area */
    if(fscanf(file, "%lx", &start_text) != 1) {
        printf("[Instruments error] [ZONE] Reading error of the initial extreme of the instrumental area\n");
        exit(EXIT_FAILURE);
    }

    if(fscanf(file, "%lx", &end_text) != 1) {
        printf("[Instruments error] [ZONE] Reading error of the final extreme of the instruated area\n");
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG_INSTR
    printf("[Instrumentation] [ZONE] Extremes of the instrumental area [%lx, %lx]\n", start_text, end_text);
#endif

    /* Alloco and initials the data structure containing the instrument map to go to the Linux kernel*/
    my_ioctl_data = (struct ioctl_data *)malloc(sizeof(struct ioctl_data));

    if(my_ioctl_data == NULL) {
        perror("[Instruments error] Memory allocation error for the instrument map");
        exit(EXIT_FAILURE);
    }

    /* Septum the beginning of the instrumental memory area taking into account the base of the mapping */
    my_ioctl_data->start_text = start_text + (unsigned long)(param->data);

    /* Set  the end of the instrumental memory area taking into account the base of the mapping */
    my_ioctl_data->end_text = end_text + (unsigned long)(param->data);

    /* Septum the number of calls that will be instructed by Loader ELF */
    my_ioctl_data->call_num  = param->num_istr_call;

    if(param->num_istr_call == 0) {
#ifdef DEBUG_INSTR
        printf("[Instrumentation] There are no calls to instruct\n");
#endif
        my_ioctl_data->call_array = NULL;
    } else {
        my_ioctl_data->call_array = (unsigned long *)calloc(my_ioctl_data->call_num, sizeof(unsigned long));

        if((my_ioctl_data->call_array) == NULL) {
            perror("[Instruments error] Error allocation of array of instructions memory addressesINT 0xFF");
            exit(EXIT_FAILURE);
        }
    }

    /* Setto il numero di RET che verranno instrumentate dal Loader ELF */
    my_ioctl_data->ret_num = param->num_istr_ret;

    if(param->num_istr_ret == 0) {
#ifdef DEBUG_INSTR
        printf("[INSTRUMENTAZIONE] Non ci sono CALL da instrumentare\n");
#endif
        my_ioctl_data->ret_array = NULL;
    } else {
        my_ioctl_data->ret_array  = (unsigned long *)calloc(my_ioctl_data->ret_num, sizeof(unsigned long));

        if((my_ioctl_data->ret_array) == NULL) {
            perror("[ERRORE INSTRUMENTAZIONE] Errore allocazione array di indirizzi di memoria dei byte 0x06");
            exit(EXIT_FAILURE);
        }
    }
#endif //IOCTL_INSTRUM_MAP

    /* Verifico se esistono delle istruzioni di CALL da instrumentare */
    if(param->num_istr_call == 0) goto no_call_instr;

    /* Setto il contatore che mantiene il numero di CALL che sono state processate */
    num_istr_did = 0;

#ifdef DEBUG_INSTR
    printf("[INSTRUMENTAZIONE] [CALL] Nome della directory contenente le informazioni per instrumentare le CALL: %s\n", dir_path_call);
#endif

    /* Apro la directory per recuperare gli offset delle istruzioni di CALL da instrumentare */
    dir = opendir(dir_path_call);

    if(dir == NULL) {
        perror("[ERRORE INSTRUMENTAZIONE] [CALL] Errore nell'apertura della directory contenente le informazioni per instrumentare le CALL");
        exit(EXIT_FAILURE);
    }

    /* Eseguo una scansione dei file presenti nella directory */

    while((entry = readdir(dir)) != NULL) {

        /* Verifico se ho a che fare con un file regolare */

        if(entry->d_type == DT_REG) {
    
            /* Pulisco il contenuto del buffer di memoria */
            memset(filename_instr, 0, 256);

            /* Costruisco il nome del file */
            strcpy(filename_instr, dir_path_call);
            strcpy(filename_instr + strlen(filename_instr), entry->d_name);

#ifdef DEBUG_INSTR
            printf("[INSTRUMENTAZIONE] [CALL] Nome file completo: %s\n", filename_instr);
#endif

            /* Devo escludere il file contenente il numero totale delle istruzioni di CALL poiché non contiene alcun offset */
            if(!strcmp(file_path_number_call, filename_instr)) continue;

            /* Apro il corrente file per recuperare gli offset delle CALL */
            file = fopen(filename_instr, "r");

            if(file == NULL) {
                perror("[ERRORE INSTRUMENTAZIONE] [CALL] Errore apertura del file contenente gli offset per le CALL");
                exit(EXIT_FAILURE);
            }

            /*
             * Leggo gli offset delle istruzioni di CALL dal file. Ogni riga del file contiene le seguenti informazioni:
             *
             * 1. Offset della istruzione di CALL all'interno dell'eseguibile espresso in esadecimale.
             * 2. Un intero che indica se questa CALL invoca una funzione che può portare a degli scenari di tipo IN.
             * 3. L'identificativo numerico della funzione che viene invocata tramite questa CALL.
             * 4. Il nome della funzione che viene invocata tramtie questa CALL.
             *
             * Il valore intero 'is_in' consente di scartare la funzione se il Loader ELF è stato compilato in modo da
             * non considerare gli scenari di tipo IN.
             */

            while(fgets(linea, sizeof(linea), file) != NULL) {

                /* Pulisco il contenuto del buffer di memoria */
                memset(func_name, 0, 256);

                if(sscanf(linea, "%lx,%d,%d,%s", &offset_instr, &is_in, &id_func, func_name) == 4) {

#ifndef WITH_IN
                    /*
                     * Se il Loader ELF è stato compilato per scartare le funzioni che possono portare a scenari di tipo IN
                     * allora bisogna verificare se la CALL corrente è associata ad una funzione di questo tipo. In tal caso,
                     * è necessario scartare la CALL e passare a quella successiva.
                     */
                
                    if(is_in == 1) {
                        //printf("[INSTRUMENTAZIONE] [CALL] La funzione '%s' potrebbe generare degli scenari di tipo IN. Il Loader ELF è stato compilato per ignorarla...\n", func_name);
                        continue;
                    }
#endif

#ifdef RANDOM_SUBSET_FUNC
#ifndef WITH_IN
#ifdef DEBUG_RAND_FUNC
                    printf("nome: %s    id_funzione: %d     contatore: %d   offset: %lx\n", func_name, id_func, counter_no_is_in_func, offset_instr);
#endif
#endif
#endif

#ifdef RANDOM_SUBSET_FUNC

#ifndef WITH_IN
                    if(last_id_func == -1) {
                        last_id_func = id_func;
                    }

                    if(id_func != last_id_func) {
                        counter_no_is_in_func++;
                        last_id_func = id_func;
                    }
#endif

                    /*
                     * Verifichiamo se la funzione a cui è associata la CALL corrente è stata scelta randomicamente. Se il
                     * Loader ELF è stato compilato consentendo gli scenari di tipo IN allora gli identificativi numerici
                     * randomici contenuti all'interno della lista possono essere confrontati con l'identificativo numerico
                     * della funzione presente nella riga che è stata letta dal file. Tuttavia, se non vengono considerate
                     * le funzioni che potrebbero portare a degli scenari di tipo IN allora la generazione randomica degli
                     * identificativi di funzione viene fatta considerando come numero solamente un sottoinsieme di tutte
                     * le funzioni considerate come 'buone'. In questo caso, non è possibile confrontare l'identificativo
                     * numerico della funzione con gli identificativi randomici nella lista poiché l'identiticativo numerico
                     * che è scritto nella riga tiene conto anche delle eventuali funzioni IN che lo precedono nel file.
                     * Per risolvere il problema utilizziamo un contatore che rappresenta il numero della corrente funzione
                     * 'non IN' partendo dal valore 0 poiché la generazione randomica include anche questo valore. 
                     */

                    is_used = false;

                    curr_random_idx = random_idx_list_head;

                    while(curr_random_idx != NULL) {
#ifdef WITH_IN
                        if(curr_random_idx->idx == id_func) {
#else
                        if(curr_random_idx->idx == counter_no_is_in_func) {
#endif //WITH_IN
                            /* La funzione associata alla CALL corrente è tra le funzioni scelta per l'instrumentazione */
                            is_used = true;
                            break;
                        }

                        curr_random_idx = curr_random_idx->next;
                    }

                    if(!is_used) {
                        continue;
                    }


#ifdef DEBUG_RAND_FUNC
                    printf("Offset CALL: %lx\n", offset_instr);
#endif
#endif //RANDOM_SUBSET_FUNC

#ifdef DEBUG_INSTR
                    printf("[INSTRUMENTAZIONE] [CALL] ET_DYN - Valore Offset istruzione di CALL corrente: %lx\n", offset_instr);
#endif

                    byte = param->data + offset_instr;

                    /* Si verifica se effettivamente è presente un'istruzione di CALL all'offset recuperato */

                    if(byte[0] != 0xE8) {
                        printf("[ERRORE INSTRUMENTAZIONE] [CALL] All'offset %lx [%lx] prestabilito non è presente un'istruzione di CALL (%x %x %x %x %x %x)\n",
                        (unsigned long)byte,
                        offset_instr,
                        byte[0], byte[1], byte[2], byte[3], byte[4], byte[5]);
                        exit(EXIT_FAILURE);
                    } else {
#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [CALL] All'offset %lx il codice operativo è effettivamente %x\n", (unsigned long)byte, byte[0]);
#endif
                        /* Calcolo l'operando corrente dell'istruzione di CALL   */

                        operand = ( (int) byte[1]   )     |                                                               
                                  (((int) byte[2]) << 8 ) |
                                  (((int) byte[3]) << 16) |
                                  (((int) byte[4]) << 24);

                        /* Calcolo l'inidirizzo della funzione target */

                        address = (unsigned long) (((unsigned long)&byte[5]) + operand);

#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [CALL] Indirizzo target trovato per la CALL ad offset %lx: %lx\n", offset_instr, address);
#endif

                        /* Popolo l'area di memoria associata a questa istruzione di CALL */

                        /* INT 0xFF */
                        ((param->new_mapp_area)[num_istr_did]).byte1 = 0xCD;
                        ((param->new_mapp_area)[num_istr_did]).byte2 = 0xFF;

                        /* NOP */
                        ((param->new_mapp_area)[num_istr_did]).byte3 = 0x66;
                        ((param->new_mapp_area)[num_istr_did]).byte4 = 0x90;

                        /* NOP */
                        ((param->new_mapp_area)[num_istr_did]).byte5 = 0x66;
                        ((param->new_mapp_area)[num_istr_did]).byte6 = 0x90;

                        /* NOP */
                        ((param->new_mapp_area)[num_istr_did]).byte7 = 0x66;
                        ((param->new_mapp_area)[num_istr_did]).byte8 = 0x90;

                        /* Indirizzo assoluto della funzione target a cui il Kernel passerà il controllo  */
                        ((param->new_mapp_area)[num_istr_did]).abs_address_func = (unsigned long)address;

                        /* Indirizzo di ritorno da posizionare sullo stack utente e sul nuovo stack kernel */
                        ((param->new_mapp_area)[num_istr_did]).ret_addr = (unsigned long)&byte[5];

#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [CALL] Indirizzo della new_mapp_area corrispondente: %lx\n", (unsigned long)&((param->new_mapp_area)[num_istr_did]));
                        printf("[INSTRUMENTAZIONE] [CALL] Indirizzo RIP: %lx\n", (unsigned long)&byte[5]);
#endif


#ifdef IOCTL_INSTRUM_MAP
                        /* Registro l'offset dell'istruzione macchina INT 0xFF da comunicare al Kernel Linux */    
                        (my_ioctl_data->call_array)[num_istr_did] = (unsigned long)(&((param->new_mapp_area)[num_istr_did].byte1));
#ifdef DEBUG_IOCTL_FUNC
                        printf("[INSTRUMENTAZIONE] [CALL] Offset call #%d = %lx\n", num_istr_did, (my_ioctl_data->call_array)[num_istr_did]);
#endif
#endif //IOCTL_INSTRUM_MAP
                        

                        /* Calcolo il nuovo operando tenendo conto delle relazioni tra le posizioni in memoria */
 
                        if((int)(((unsigned long)&((param->new_mapp_area)[num_istr_did])) - ((unsigned long)(&byte[5]))) > 0) {

                            new_operand = (int)((((unsigned long)(&byte[5]) - (unsigned long)&((param->new_mapp_area)[num_istr_did]))));
#ifdef DEBUG_INSTR
                            printf("[INSTRUMENTAZIONE] [CALL] La nuova area di memoria si trova più in alto del RIP\n");
                            printf("[INSTRUMENTAZIONE] [CALL] Displacement: %x\n", new_operand);
#endif

                        } else {                            
                            
                            new_operand = (int)((((unsigned long)(&byte[5]) - (unsigned long)&((param->new_mapp_area)[num_istr_did]))));
                            new_operand = -new_operand;
#ifdef DEBUG_INSTR
                            printf("[INSTRUMENTAZIONE] [CALL] Displacement: %x\n", new_operand);
                            printf("[INSTRUMENTAZIONE] [CALL] La nuova area di memoria si trova più in basso del RIP\n");
#endif                      
                        }

                        /* Mettiamo l'istruzione di JMP con il corretto operando */
                        byte[4] = ((unsigned char *)&new_operand)[3];
                        byte[3] = ((unsigned char *)&new_operand)[2];
                        byte[2] = ((unsigned char *)&new_operand)[1];
                        byte[1] = ((unsigned char *)&new_operand)[0];
                        byte[0] = 0xE9;

#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [CALL] Valore effettivo della JMP target: %p\tIndirizzo della struttura dati relativa: %p\n", (void *)((unsigned long)&byte[5] + new_operand), (void *)&((param->new_mapp_area)[num_istr_did]));
#endif                        
                        num_istr_did++;

#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [CALL] Instrumentazione eseguita con successo\n");
                        fflush(stdout);
#endif
                    }                   
                    
                } else {
                    printf("[ERRORE INSTRUMENTAZIONE] [CALL] Valore non valido\n");
                    exit(EXIT_FAILURE);
                }

            }
            
            fclose(file);
        }
    }

no_call_instr:

#ifdef DEBUG_INSTR
    printf("[INSTRUMENTAZIONE] [RET] Nome della directory contenente le informazioni per instrumentare le RET: %s\n", dir_path_ret);
#endif

    if(param->num_istr_ret == 0) goto no_ret_instr;

    /* Setto il contatore che mantiene il numero di RET che sono state processate */
    num_istr_did = 0;

    /* Apro la directory per recuperare gli offset delle istruzioni di RET */
    dir = opendir(dir_path_ret);

    if(dir == NULL) {
        perror("[ERRORE INSTRUMENTAZIONE] [RET] Errore nell'apertura della directory contenente le informazioni per instrumentare le RET");
        exit(EXIT_FAILURE);
    }

#ifdef RANDOM_SUBSET_FUNC
#ifndef WITH_IN
    counter_no_is_in_func = 0;
    last_id_func = -1;
#endif
#endif

    /* Eseguo una scansione dei file presenti nella directory */

    while((entry = readdir(dir)) != NULL) {

        /* Verifico se ho a che fare con un file regolare */

        if(entry->d_type == DT_REG) {

            /* Pulisco il contenuto del buffer di memoria */
            memset(filename_instr, 0, 256);

            /* Costruisco il nome del file */
            strcpy(filename_instr, dir_path_ret);
            strcpy(filename_instr + strlen(filename_instr), entry->d_name);

#ifdef DEBUG_INSTR
            printf("[INSTRUMENTAZIONE] [RET] Nome file completo: %s\n", filename_instr);
#endif

            /* Devo escludere il file contenente il numero totale delle istruzioni di CALL poiché non contiene alcun offset */
            if(!strcmp(file_path_number_ret, filename_instr)) continue;

            /* Apro il corrente file per recuperare gli offset delle RET */
            file = fopen(filename_instr, "r");

            if(file == NULL) {
                perror("[ERRORE INSTRUMENTAZIONE] [RET] Errore apertura del file contenente gli offset per le RET");
                exit(EXIT_FAILURE);
            }

            /* Leggo gli offset delle istruzioni di RET dal file */

            while(fgets(linea, sizeof(linea), file) != NULL) {

                memset(func_name, 0, 256);

                if(sscanf(linea, "%lx,%d,%d,%s", &offset_instr, &is_in, &id_func, func_name) == 4) {

#ifndef WITH_IN
                    /*
                     * Se il Loader ELF è stato compilato per scartare le funzioni che possono portare a scenari di tipo IN
                     * allora bisogna verificare se la CALL corrente è associata ad una funzione di questo tipo. In tal caso,
                     * è necessario scartare la CALL e passare a quella successiva.
                     */
                
                    if(is_in == 1) {
                        //printf("[INSTRUMENTAZIONE] [RET] La funzione '%s' potrebbe generare degli scenari di tipo IN. Il Loader ELF è stato compilato per ignorarla...\n", func_name);
                        continue;
                    }
#endif

#ifdef RANDOM_SUBSET_FUNC
#ifndef WITH_IN
#ifdef DEBUG_RAND_FUNC
                    printf("nome: %s    id_funzione: %d     contatore: %d   offset: %lx\n", func_name, id_func, counter_no_is_in_func, offset_instr);
#endif
#endif
#endif


#ifdef RANDOM_SUBSET_FUNC

#ifndef WITH_IN
                    if(last_id_func == -1) {
                        last_id_func = id_func;
                    }

                        /* Aggiorno l'identificativo numerico che avrà la prossima funzione non IN tra tutte le funzioni non IN */
                    if(id_func != last_id_func) {
                        counter_no_is_in_func++;
                        last_id_func = id_func;
                    }
#endif

                    /* Verifichiamo se la funzione a cui è associata la RET corrente è stata scelta randomicamente */

                    is_used = false;

                    curr_random_idx = random_idx_list_head;

                    while(curr_random_idx != NULL) {
#ifdef WITH_IN
                        if(curr_random_idx->idx == id_func) {
#else
                        if(curr_random_idx->idx == counter_no_is_in_func) {
#endif //WITH_IN
                            /* La funzione associata alla CALL corrente è tra le funzioni scelta per l'instrumentazione */
                            is_used = true;
                            break;
                        }

                        curr_random_idx = curr_random_idx->next;
                    }

                    if(!is_used) {
                        continue;
                    }

#ifdef DEBUG_RAND_FUNC
                    printf("Offset RET: %lx\n", offset_instr);
#endif

#endif //RANDOM_SUBSET_FUNC

#ifdef DEBUG_INSTR
                    printf("[INSTRUMENTAZIONE] [RET] ET_DYN - Valore Offset istruzione di RET corrente: %lx\n", offset_instr);
#endif

                    byte = param->data + offset_instr;

                    /* Si verifica se effettivamente è presente un'istruzione di CALL all'offset recuperato */

                    if(byte[0] != 0xC3) {
                        printf("[ERRORE INSTRUMENTAZIONE] [RET] All'offset %lx prestabilito non è presente un'istruzione di RET (%x)\n", (unsigned long)byte, byte[0]);
                        exit(EXIT_FAILURE);
                    } else {
#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [RET] All'offset %lx il codice operativo è effettivamente %x\n", offset_instr, byte[0]);
#endif
                        /* Inserisco un byte che non rappresenta l'inizio di Opcode di alcuna istruzione macchina */
                        byte[0] = 0x06;

#ifdef IOCTL_INSTRUM_MAP
                        /* Registro l'offset dell'istruzione macchina INT 0xFF da comunicare al Kernel Linux */    
                        (my_ioctl_data->ret_array)[num_istr_did] = (unsigned long)(&byte[0]);
#ifdef DEBUG_IOCTL_FUNC
                        printf("[INSTRUMENTAZIONE] [RET] Offset ret #%d = %lx\n", num_istr_did, (my_ioctl_data->ret_array)[num_istr_did]);
#endif
                        num_istr_did++;
#endif //IOCTL_INSTRUM_MAP

#ifdef DEBUG_INSTR
                        printf("[INSTRUMENTAZIONE] [RET] Instrumentazione eseguita con successo\n");
                        fflush(stdout);
#endif
                    }                   
                    
                } else {
                    printf("[ERRORE INSTRUMENTAZIONE] [RET] Valore non valido\n");
                    exit(EXIT_FAILURE);
                }

            }
            
            fclose(file);
        }
    }

no_ret_instr:

    fd = open(node, O_WRONLY);

    if(fd == -1) {
        perror("[ERRORE INSTRUMENTAZIONE] Errore apertura del nodo in /proc");
        exit(EXIT_FAILURE);
    }

    /* Richiedo al Kernel Linux di allocare e inizializzare i metadati di sicurezza */

#ifdef LOG_SYSTEM
    /* Popolo la struttura dati contenente le informazioni di monitoraggio */

    lsi.memory_mapped_base = (unsigned long)param->data;

    lsi.id_user = param->id_user;

    /* Estraggo il nome del programma da lanciare dal percorso assoluto */
    last_occ = strrchr(param->input_file, '/');

    if(last_occ == NULL) {
        printf("[ERRORE INSTRUMENTAZIONE] Errore nella estrazione del nome dal percorso assoluto '%s'\n", param->input_file);
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* Alloco memoria per il nome del nuovo progrramma */
    lsi.program_name = (char *)malloc(strlen(last_occ + 1) + 1);

    if(lsi.program_name == NULL) {
        printf("[ERRORE INSTRUMENTAZIONE] Errore nella allocazione di memoria per il nome del programma\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* Azzero il contenuto del buffer di memoria per ospitare il nome del nuovo programma */
    memset(lsi.program_name, 0, strlen(last_occ + 1) + 1);

    /* Copio tra le informazioni di monitoraggio il nome del programma che bisogna lanciare */
    strncpy(lsi.program_name, last_occ + 1, strlen(last_occ + 1));

    //printf("[INSTRUMENTAZIONE] Nome del programma che deve essere lanciato dal Loader ELF: %s\n", lsi.program_name);

    lsi.len = strlen(last_occ + 1) + 1;

    if(ioctl(fd, SECURITY_METADATA, &lsi)) {
        perror("[ERRORE INSTRUMENTAZIONE] Errore richiesta allocazione e inizializzazione dei metadati di sicurezza");
        close(fd);
        exit(EXIT_FAILURE);
    }
#else
    if(ioctl(fd, SECURITY_METADATA)) {
        perror("[ERRORE INSTRUMENTAZIONE] Errore richiesta allocazione e inizializzazione dei metadati di sicurezza");
        close(fd);
        exit(EXIT_FAILURE);
    }
#endif

#ifdef IOCTL_INSTRUM_MAP
    /* Comunica al Kernel Linux la mappa di istrumentazione user space              */
    if(ioctl(fd, INSTRUM_MAP, (struct ioctl_data *)my_ioctl_data)) {
        perror("[ERRORE INSTRUMENTAZIONE] Errore comunicazione della mappa di instrumentazione user space");
        close(fd);
        exit(EXIT_FAILURE);
    }
#endif //IOCTL_INSTRUM_MAP

    close(fd);
}

/*
 * init_path - Inizializza i percorsi assoluti utilizzati dal Loader ELF per ricavare le informazioni
 * necessarie a instrumentare il nuovo eseguibile da lanciare.
 *
 * @path_instr_info: Percorso assoluto della directory contenente le informazioni di instrumentazione 
 */
void init_path(char *path_instr_info) {

    /* Settagio percorso assoluto del file contenente il numero delle istruzioni di CALL */
    strcpy(file_path_number_call, path_instr_info);
    strcpy(file_path_number_call + strlen(file_path_number_call), file_path_number_suf_call);

    /* Settagio percorso assoluto del file contenente il numero delle istruzioni di RET */
    strcpy(file_path_number_ret, path_instr_info);
    strcpy(file_path_number_ret + strlen(file_path_number_ret), file_path_number_suf_ret);

    /* Settagio percorso assoluto della cartella contenente i file con gli offset delle istruzioni di CALL */
    strcpy(dir_path_call, path_instr_info);
    strcpy(dir_path_call + strlen(dir_path_call), dir_path_call_suf);

    /* Settagio percorso assoluto della cartella contenente i file con gli offset delle istruzioni di RET */
    strcpy(dir_path_ret, path_instr_info);
    strcpy(dir_path_ret + strlen(dir_path_ret), dir_path_ret_suf);

#ifdef DEBUG_MAP_ELF
    printf("[INIZIALIZZAZIONE PERCORSI] Percorso assoluto del file contenente il numero di CALL: %s\n", file_path_number_call);
    printf("[INIZIALIZZAZIONE PERCORSI] Percorso assoluto del file contenente il numero di RET: %s\n", file_path_number_ret);
    printf("[INIZIALIZZAZIONE PERCORSI] Percorso assoluto della cartella contenente i file con gli offset delle istruzioni di CALL: %s\n", dir_path_call);
    printf("[INIZIALIZZAZIONE PERCORSI] Percorso assoluto della cartella contenente i file con gli offset delle istruzioni di RET: %s\n", dir_path_ret);
#endif
}




/* ---------------------------------------FINE ROBA AGGIUNTA-------------------------------------------------- */

// This takes a native-sized EHDR, but the parts we check are in the
// constant-sized bit so it doesn't really matter
// TODO: multilib and ehdr->e_machine checking
bool is_compatible_elf(const ElfW(Ehdr) *ehdr) {
	return (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
			ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
			ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
			ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
			ehdr->e_ident[EI_CLASS] == ELFCLASS_NATIVE &&
			ehdr->e_ident[EI_DATA] == ELFDATA_NATIVE);
}

/**
 * map_elf - Memory Mapping di un file ELF. L'instrumentazione viene eseguita solamente sul nuovo file da lanciare
 * e non viene eseguita sull'eventuale interprete del nuovo programma.
 *
 * @data           : Puntatore alla zona di memoria contenete la DISK VIEW del file ELF da lanciare
 * @obj            : Puntatore ad una struttura dati 'struct mapped_elf' relativa al file ELF da lanciare
 * @is_interp      : Indica se il file da mappare è il file ELF da lanciare oppure il suo interprete
 * @path_instr_info: Percorso assoluto della directory contenente le informazioni di instrumentazione 
 * @input_file     : Percorso assoluto del nuovo file da caricare
 * @id_user        : Identificativo numerico utente utilizzato per creare i file di LOG
 */
#ifdef LOG_SYSTEM
#ifdef RAND_PERC
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info, char *input_file, int id_user, int perc)
#else
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info, char *input_file, int id_user)
#endif
#else
#ifdef RAND_PERC
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info, int perc)
#else
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info)
#endif
#endif
{
	ElfW(Addr) dest = 0;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;

	unsigned char *mapping = MAP_FAILED;
	const unsigned char *source = 0;
	size_t len, virtual_offset = 0, total_to_map = 0;
	int ii, prot;

/* ---------------------------------------ROBA AGGIUNTA------------------------------------------------------ */
    
    int ret;
    FILE *file = NULL;

    /* Informazioni necessarie per eseguire l'instrumentazione del programma da lanciare         */
    instrum_param param;

    /* Identifica la tipologia di eseguibile ELF con cui abbiamo a che fare                      */
    int et_dyn;

    /* Numero delle istruzioni di CALL nel programma da lanciare che devono essere instrumentate */                   
    unsigned int num_istr_call;

    /* Numero delle istruzioni di RET nel programma da lanciare che devono essere instrumentate  */                                    
    unsigned int num_istr_ret;

    /* Puntatore alla nuova area di memoria contenente le informazioni per instrumentare le CALL */                        
    struct instru_call_info *new_mapp_area = NULL;

    /* Puntatore ad un elemento mantenente le informazioni relative ad un segmento dell'eseguibile ELF */
    info_seg *item;  

/* ---------------------------------------FINE ROBA AGGIUNTA-------------------------------------------------- */

	/* Recupero il puntatore all'intestazione ELF       */
	ehdr = (ElfW(Ehdr) *)data;

    /* Recupero il puntatore alla Program Header Table  */
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

/* ---------------------------------------ROBA AGGIUNTA------------------------------------------------------ */

    /*
     * Determino la tipologia del file ELF da lanciare. L'architettura di sicurezza è stata implementata per
     * gestire SOLAMENTE eseguibili di tipo ET_DYN che consentono al Kernel di posizionarli in modo randomico
     * nello spazio di indirizzamento (ASLR).
     */

    if(ehdr->e_type == ET_DYN) {
#ifdef DEBUG_MAP_ELF
        printf("[ELF MAP] L'eseguibile da lanciare è di tipo ET_DYN\n");
#endif      
        et_dyn = 1;        
    }
    else if(ehdr->e_type == ET_EXEC) {
#ifdef DEBUG_MAP_ELF
        printf("[ELF MAP] L'eseguibile da lanciare è di tipo ET_EXEC\n");
#endif 
        et_dyn = 0;
    }
    else {
        printf("[ERRORE ELF MAP] La tipologia del'eseguibile da lanciare è differente da ET_DYN e da ET_EXEC...\n");
        exit(EXIT_FAILURE);    
    }

    /* Inizializzo i percorsi assoluti utilizzati dal Loader ELF per recuperare le informazioni di instrumentazione */
    if(path_instr_info != NULL) init_path(path_instr_info);
    
/* ---------------------------------------FINE ROBA AGGIUNTA-------------------------------------------------- */

	/* Calcola la quantità di memoria totale che deve essere mmappata per l'eseguibile ELF */

	for(ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {

        /* Verifico se il segmento corrente deve essere caricato in memoria */

		if(phdr->p_type == PT_LOAD) {

			total_to_map = ((phdr->p_vaddr + phdr->p_memsz) > total_to_map
					? phdr->p_vaddr + phdr->p_memsz
					: total_to_map);
#ifdef DEBUG_MAP_ELF
			dprint("total mapping is now %08zx based on %08zx seg at %p\n", total_to_map, phdr->p_memsz, (void *)phdr->p_vaddr);
#endif
		}
	}

	// Reset phdr
	phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

    /* Carico nella MEMORY VIEW i segmenti del nuovo eseguibile che sono di tipo PT_LOAD */

	for(ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {

		if(phdr->p_type == PT_LOAD) {

            /*
             * Verifico se è il primo segmento PT_LOAD da caricare in memoria. In questo caso, alloco il buffer
             * di memoria che conterrà la MEMORY VIEW per il nuovo processo e il buffer di memoria che conterrà
             * le informazioni di intstrumentazione per le istruzioni di CALL (i.e., quelle informazioni che il
             * Kernel Linux recupererà all'interno del gestore della Spurious Interrupt).            
             */

			if(mapping == MAP_FAILED) {

				// Setup area in memory to contain the new binary image

				if (phdr->p_vaddr != 0) {
					// The first loadable segment has an address, so we are not PIE and need to readjust our perspective
					total_to_map -= phdr->p_vaddr;
				}

				mapping = mmap((void *)PAGE_FLOOR(phdr->p_vaddr), PAGE_CEIL(total_to_map), PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

				if(mapping == MAP_FAILED) {
					dprint("Failed to mmap() 1: %s\n", strerror(errno));
					goto map_failed;
				}

                /* Azzero il contenuto della nuova area di memoria mappata */
				memset(mapping, 0, total_to_map);

				//dprint("data @ %p, mapping @ %p\n", data, mapping);

				if(phdr->p_vaddr == 0) virtual_offset = (size_t) mapping;

				obj->ehdr = (ElfW(Ehdr) *) mapping;
				obj->entry_point = virtual_offset + ehdr->e_entry;

/* ---------------------------------------ROBA AGGIUNTA------------------------------------------------------ */

                /* Recupero il numero totale di istruzioni di RET da instrumentare */
                file = fopen(file_path_number_ret, "r");

                if(file == NULL) {
                    perror("[ERRORE ELF MAP] Errore apertura file per la lettura del numero totale di istruzioni di RET\n");
                    exit(EXIT_FAILURE);
                }

                ret = fscanf(file, "%u", &num_istr_ret);

                if(ret != 1) {
                    printf("[ERRORE ELF MAP] Errore nella lettura del numero di istruzioni di RET\n");
                    exit(EXIT_FAILURE);
                }

                fclose(file);

#ifdef DEBUG_MAP_ELF
                printf("[ELF MAP] Numero totale di istruzioni di RET: %d\n", num_istr_ret);
#endif

                /* Recupero il numero totale di istruzioni di CALL da instrumentare */                
                file = fopen(file_path_number_call, "r");

                if(file == NULL) {
                    perror("[ERRORE ELF MAP] Errore apertura file per la lettura del numero totale di istruzioni di CALL\n");
                    exit(EXIT_FAILURE);
                }

                ret = fscanf(file, "%u", &num_istr_call);

                if(ret != 1) {
                    printf("[ERRORE ELF MAP] Errore nella lettura del numero di istruzioni di CALL\n");
                    exit(EXIT_FAILURE);
                }

#ifdef DEBUG_MAP_ELF
                printf("[ELF MAP] Numero totale di istruzioni di CALL: %d\n", num_istr_call);
#endif        
                fclose(file);

                if(num_istr_call == 0) goto no_call_istr;                

                /*
                 * Mappo la nuova area di memoria in cui mantenere le informazioni relative alle istruzioni di CALL.
                 * Questa nuova area di memoria è posizionata subito sotto la zona di memoria dei segmenti ELF in
                 * modo da sfruttare al meglio l'offset della istruzione di JMP che andrà a sostituire la CALL.
                 */

				new_mapp_area = (struct instru_call_info *)mmap(mapping - PAGE_CEIL(sizeof(struct instru_call_info) * num_istr_call),
                                 PAGE_CEIL(sizeof(struct instru_call_info) * num_istr_call),
                                 PROT_WRITE | PROT_EXEC | PROT_READ,
                                 MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

				if(new_mapp_area == MAP_FAILED) {
					dprint("Failed to mmap() 2: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

#ifdef DEBUG_MAP_ELF
                printf("[MAP ELF] Indirizzo della regione di memoria contenente le informazioni per la simulazione delle CALL: %p\n",
                (void *)new_mapp_area);
#endif
/* ---------------------------------------FINE ROBA AGGIUNTA------------------------------------------------------ */            
			}

no_call_istr:
            /* Copio il segmento dalla zona di memoria DISK VIEW alla zona di memoria MEMORY VIEW */

			source = data + phdr->p_offset;
			dest = virtual_offset + phdr->p_vaddr;
			len = phdr->p_filesz;

#ifdef DEBUG_MAP_ELF
			dprint("memcpy(%p, %p, %08zx)\n", (void *)dest, source, len);
#endif
			memcpy((void *)dest, source, len);

            /* Setto correttamente le protezioni del segmento in accordo a quanto scritto nel program header dell'ELF */

			prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
				    ((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
				    ((phdr->p_flags & PF_X) ? PROT_EXEC : 0));

			if(mprotect((void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz), prot) != 0) {
				goto mprotect_failed;
			}

/* ---------------------------------------ROBA AGGIUNTA------------------------------------------------------ */

            /* Salvo le informazioni per il segmento corrente all'interno della lista */
            item = (info_seg *)malloc(sizeof(info_seg));

            if(item == NULL) {
                printf("[ERRORE MAP ELF] Errore allocazione di memoria per le informazioni di un segmento dell'eseguibile ELF\n");
                exit(EXIT_FAILURE);
            }

            item->dest = dest;
            item->size = phdr->p_memsz;
            item->prot = prot;

            /* Inserimento in testa alla lista */
            item->next = info_seg_head;
            info_seg_head = item;
/* ---------------------------------------------------------------------------------------------------------- */

		} else if(phdr->p_type == PT_INTERP) {
			// Since PT_INTERP must come before any PT_LOAD segments, store the
			// offset for now and add the base mapping at the end
			obj->interp = (char *) phdr->p_offset;
		}

	}

    /*
     * Verifico se la funzione map_elf() è stata invocata per il nuovo programma da lanciare oppure per il relativo
     * interprete. Nel caso in cui stiamo mappando il nuovo programma allora eseguiamo la fase di instrumentazione.
     */

    if(!is_interp) {

        /*
         * I segmenti PT_LOAD che sono stati caricati nella MEMORY VIEW devono essere abilitati per la scrittura.
         * Infatti, la fase di instrumentazione prevede la modifica di specifici byte all'interno dell'immagine
         * del nuovo programma.
         */

        item = info_seg_head;

        while(item != NULL) {

            /*
             * Precedentemente con la mprotect ho settato le nuove protezioni per il segmento corrente che sono dichiarate
             * nell'ELF. Nel caso in cui il segmento non sia scrivibile, bisogna forzare la scrittura per poter eseguire
             * l'instrumentazione del codice. Dopo aver instrumentato il codice, il permesso di scrittura viene eventualmente
             * ripristinato in accordo a ciò che è scritto nel file ELF.
             */

            if(mprotect((void *)PAGE_FLOOR(item->dest), PAGE_CEIL(item->size), item->prot | PROT_WRITE) != 0) {
			    goto mprotect_failed;
			}

            item = item->next;

        }

        /* Eseguo l'instrumentazione delle CALL e delle RET per il segmento eseguibile corrente */

        param.data = (unsigned char *)mapping;
        param.new_mapp_area = new_mapp_area;
        param.et_dyn = et_dyn;
        param.num_istr_call = num_istr_call;
        param.num_istr_ret = num_istr_ret;

#if defined(IOCTL_INSTRUM_MAP) || defined(RANDOM_SUBSET_FUNC)
        param.path_instr_info = path_instr_info;
#endif

#ifdef LOG_SYSTEM
        param.input_file = input_file;
        param.id_user = id_user;
#endif

#ifdef RANDOM_SUBSET_FUNC
#ifdef RAND_PERC
        param.perc = perc;
#endif
#endif

        do_instrumentation(&param);

        /* Ripristino le protezioni di memoria specificate nell'eseguibile ELF */

        item = info_seg_head;

        while(item != NULL) {

            if(mprotect((void *)PAGE_FLOOR(item->dest), PAGE_CEIL(item->size), item->prot) != 0) {
			    goto mprotect_failed;
            }

            item = item->next;
        }
    }

	if(obj->interp) {
		obj->interp = (char *) mapping + (size_t) obj->interp;
	}

	return;

mprotect_failed:
	munmap(mapping, total_to_map);

map_failed:
	obj->ehdr = MAP_FAILED;
}
