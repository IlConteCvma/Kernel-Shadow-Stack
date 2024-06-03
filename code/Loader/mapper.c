#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <include/include.h>
#include <include/kss.h>

#define ELF_ARCH   ELFCLASS64
#define ELFDATA_NATIVE  ELFDATA2LSB

#define PAGE_FLOOR(addr) ((addr) & (-PAGE_SIZE))                // Lower bound to page size
#define PAGE_CEIL(addr) (PAGE_FLOOR((addr) + PAGE_SIZE - 1))    // Upper bound to page size

/* List of the list of the list containing the information on the segments of the executable */
info_seg * info_seg_head = NULL;

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

/* Information needed to perform the institution of the program to be launched         */
instrum_param param;

int is_interp_global;


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

    dprint("[Initialisation paths] Absolute path of the file containing the number of calls: %s\n", file_path_number_call);
    dprint("[Initialisation paths] Absolute path of the file containing the RET number: %s\n", file_path_number_ret);
    dprint("[Initialisation paths] Absolute path of the folder containing the files with the offset of the call instructions: %s\n", dir_path_call);
    dprint("[Initialisation paths] Absolute path of the folder containing the files with the offset of the Ret instructions: %s\n", dir_path_ret);

}


// Sanity Check
bool is_compatible_elf(const ElfW(Ehdr) *ehdr) {
    return (ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
            ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
            ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
            ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
            ehdr->e_ident[EI_CLASS] == ELF_CLASS &&
            ehdr->e_ident[EI_DATA] == ELFDATA_NATIVE);
}

#ifdef LOG_SYSTEM
    #ifdef RAND_PERC
    void map(const unsigned char *data, struct elf_info *md, int is_interp, char *path_instr_info, char *input_file, int id_user, int perc)
    #else
    void map(const unsigned char *data, struct elf_info *md, int is_interp, char *path_instr_info, char *input_file, int id_user)
    #endif
#else
    #ifdef RAND_PERC
    void map(const unsigned char *data, struct elf_info *md, int is_interp, char *path_instr_info, int perc)
    #else
    void map(const unsigned char *data, struct elf_info *md, int is_interp, char *path_instr_info)
    #endif
#endif
{
    ElfW(Ehdr) *ehdr;
    ElfW(Phdr) *phdr;

    size_t virtual_offset = 0, total_to_map = 0, success = 0;
    unsigned char *mapping = MAP_FAILED;

    int ret;
    FILE *file = NULL;



    /* Identifies the type of executable ELF with which we are dealing with                     */
    int et_dyn;

    /* Number of call instructions in the program to be launched that must be instructed*/                   
    unsigned int num_istr_call;

    /* Number of Ret instructions in the program to be launched that must be instructed */                                    
    unsigned int num_istr_ret;

    /* Pointer to the new memory area containing the information to instruct the calls*/                        
    struct instru_call_info *new_mapp_area = NULL;

    /* Pointer to an element maintaining the information relating to a segment of the ELF executable*/
    info_seg *item; 

    is_interp_global = is_interp;

    ehdr = (ElfW(Ehdr) *)data;
    phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);

    /*
     * Determine the type of the Elf file to be launched.Security architecture has been implemented for
     * Manage only ET_DYN types that allow the kernel to position them in a random way
     * in the addressing space (ASLR).
    */

    if(ehdr->e_type == ET_DYN) {
        dprint("[ELF MAP] The executable to be launched is of the typeET_DYN\n");    
        et_dyn = 1;        
    }
    else if(ehdr->e_type == ET_EXEC) {
        dprint("[ELF MAP] The executable to be launched is of the type ET_EXEC\n");
        et_dyn = 0;
    }
    else {
        printf("[ERROR ELF MAP] The type of executable to be launched is different from Et_dyn and from ET_EXEC...\n");
        exit(EXIT_FAILURE);    
    }

    /* The absolute paths used by the Elf Loader to recover the instruments information initials */
    if(path_instr_info != NULL) init_path(path_instr_info);


    // Compute only necessary memory (only PT_LOAD size)
    total_to_map = compute_total_memory_size(ehdr, phdr);

    phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff); // Reset pointer to first PT
    mapping = setup_memory(data, total_to_map, phdr, &virtual_offset, ehdr, md);
    if (mapping == MAP_FAILED){
        md->ehdr = MAP_FAILED;
        return;
    }


    //kss files
    /* Recovery the total number of Ret instructions */
    file = fopen(file_path_number_ret, "r");

    if(file == NULL) {
        perror("[ERROR ELF MAP] File opening error for reading the total number of Ret instructions\n");
        exit(EXIT_FAILURE);
    }

    ret = fscanf(file, "%u", &num_istr_ret);

    if(ret != 1) {
        printf("[ERROR ELF MAP] Reading the Ret Instructions number of instructions\n");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    dprint("[ELF MAP] Total number of Ret instructions: %d\n", num_istr_ret);

    /* recovery The Total Number Of Call Instructions */                
    file = fopen(file_path_number_call, "r");

    if(file == NULL) {
        perror("[ERROR ELF MAP] Errore apertura file per la lettura del numero totale di istruzioni di CALL\n");
        exit(EXIT_FAILURE);
    }

    ret = fscanf(file, "%u", &num_istr_call);

    if(ret != 1) {
        printf("[ERROR ELF MAP] Errore nella lettura del numero di istruzioni di CALL\n");
        exit(EXIT_FAILURE);
    }
    dprint("[ELF MAP] Total number of call instructions: %d\n", num_istr_call);
    fclose(file);
    if(num_istr_call == 0) goto no_call_istr; 

    /*
    * Map the new memory area in which to keep the information relating to the call instructions.
    * This new memory area is immediately positioned under the memory area of ​​the ELF segments in
    * In order to make the most of the offset of JMP's education that will replace the call.
    */

   //TODO control this part
    new_mapp_area = (struct instru_call_info *)mmap(mapping - PAGE_CEIL(sizeof(struct instru_call_info) * num_istr_call),
                        PAGE_CEIL(sizeof(struct instru_call_info) * num_istr_call),
                        PROT_WRITE | PROT_EXEC | PROT_READ,
                        MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if(new_mapp_area == MAP_FAILED) {
        dprint("Failed to mmap() 2: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    dprint("[MAP ELF] Address of the memory region containing the information for the simulation of the calls: %p\n",
                (void *)new_mapp_area);


no_call_istr:

    /* I perform the institution of the calls and the RETs for the current executable segment */

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

    // Write and protect segments
    success = map_segments(mapping, data, phdr, virtual_offset, total_to_map, ehdr, md);
    if (success == -1){
        munmap(mapping, total_to_map);
    }

   
}

size_t compute_total_memory_size(const ElfW(Ehdr) *ehdr, const ElfW(Phdr) *phdr) {
    size_t total_to_map = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            size_t segment_size = phdr[i].p_vaddr + phdr[i].p_memsz;
            total_to_map = (segment_size > total_to_map) ? segment_size : total_to_map;
        }
    }

    dprint("Necessary to allocate %08zx\n", total_to_map);
    return total_to_map;
}

// Setup area in memory to contain the new binary image
unsigned char *setup_memory(unsigned char *data, size_t total_to_map, ElfW(Phdr) *phdr, size_t *virtual_offset, ElfW(Ehdr) *ehdr, struct elf_info *md) {
    unsigned char *mapping = MAP_FAILED;


    for (int ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
        if (phdr->p_type == PT_LOAD) {


            if (mapping == MAP_FAILED) {        // First iteration will always be MAP_FAILED
                
                
                mapping = mmap((void *)PAGE_FLOOR(phdr->p_vaddr), PAGE_CEIL(total_to_map), PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
                if (mapping == MAP_FAILED) {
                    dprint("Failed to mmap(): %s\n", strerror(errno));
                    break;
                }
                dprint("Mapped %08zx of memory starting from %08zx\n", total_to_map, phdr->p_vaddr);

                memset(mapping, 0, total_to_map);
                
                /*
                * Position Indipendent Executable have not a virtual address on the first PHDR.
                * From 2nd program header, they have v_addr relative to the first PHDR (see readelf -l examples/homemade/hello_world)
                * Also each field of EHDR is relative to where the file will be put in memory
                */
               if (phdr->p_vaddr == 0){
                    *virtual_offset = (size_t) mapping;
                }

                // First program header contains EHDR    
                md->ehdr = (ElfW(Ehdr) *) mapping;

                // Retrive entry point to jmp
                md->entry_point = *virtual_offset + ehdr->e_entry;
            }
            // mmap was successful
            break;

        }
    }
    return mapping;
}

// Each segment will be mapped to vaddr so ther will be no conflicts and no needs of adjustments
size_t map_segments(unsigned char *mapping, unsigned char *data, ElfW(Phdr) *phdr, size_t virtual_offset, 
    size_t total_to_map, ElfW(Ehdr) *ehdr, struct elf_info *md) {
    ElfW(Addr) dest = 0;
    const unsigned char *source = 0;
    size_t len;
    int prot;
    /* Pointer to an element maintaining the information relating to a segment of the ELF executable*/
    info_seg *item; 

    phdr = (ElfW(Phdr) *)(data + ehdr->e_phoff);
    for (int ii = 0; ii < ehdr->e_phnum; ii++, phdr++) {
        if (phdr->p_type == PT_LOAD) {
            source = data + phdr->p_offset;

            // If PIE we need to put each PHD at v_addr bytes from the start of the file in memory
            // If not PIE, virtual_offset is 0
            dest = virtual_offset + phdr->p_vaddr;
            len = phdr->p_filesz;

            memcpy((void *)dest, source, len);

            prot = (((phdr->p_flags & PF_R) ? PROT_READ : 0) |
                    ((phdr->p_flags & PF_W) ? PROT_WRITE: 0) |
                    ((phdr->p_flags & PF_X) ? PROT_EXEC : 0));
            if (mprotect((void *)PAGE_FLOOR(dest), PAGE_CEIL(phdr->p_memsz), prot) != 0) {
                return -1;
            }

            /* Except for information for the current segment within the list */
            item = (info_seg *)malloc(sizeof(info_seg));

            if(item == NULL) {
                printf("[ERROR MAP ELF] Memory allocation error for information from an ELF executable segment\n");
                exit(EXIT_FAILURE);
            }

            item->dest = dest;
            item->size = phdr->p_memsz;
            item->prot = prot;

            /* Insertion at the top of the list */
            item->next = info_seg_head;
            info_seg_head = item;

        } else if (phdr->p_type == PT_INTERP) {
            dprint("Found PT_INTERP\n");
            md->interp = (char *) phdr->p_offset;      // Only store offset, see below
        }
    }


     //instrumentation kss

    /*
     * I check if the Map_elf () function has been invoked for the new program to be launched or for the relative
     * interpreter.In the event that we are worlding the new program then we perform the instrument phase.
    */

    if(!is_interp_global) {
        /*
         * The PT_LOAD segments that have been loaded into the memory view must be enabled for writing.
         * In fact, the instrument phase provides for the modification of specific bytes within the image
         * of the new program.
        */
        item = info_seg_head;
        while(item != NULL) {

            /*
             * Previously with Mprotect I set the new protections for the current segment that are declared
             * in the ELF.In the event that the segment is not written, the writing must be forced to be able to perform
             * the institution of the code.After instructing the code, the writing permit comes possibly
             * Restored in accordance with what is written in the Elf file.
            */

            if(mprotect((void *)PAGE_FLOOR(item->dest), PAGE_CEIL(item->size), item->prot | PROT_WRITE) != 0) {
			    goto mprotect_failed;
			}

            item = item->next;

        }

        

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

    if (md->interp) {
        // The intepreter will be mapped after malicious ELF
        // It must come before
        md->interp = (char *) mapping + (size_t) md->interp;
    }

    return 1;
mprotect_failed:
	munmap(mapping, total_to_map);
    return -1;

map_failed:
    obj->ehdr = MAP_FAILED;
    return -1;
}