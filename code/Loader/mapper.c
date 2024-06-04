#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include "include/include.h"
#include "include/kss.h"

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
const char *node = "/proc/kss_node";       /* Path of the node in /proc to communicate the activities to be performed at the kernel*/

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

        param.path_instr_info = path_instr_info;


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