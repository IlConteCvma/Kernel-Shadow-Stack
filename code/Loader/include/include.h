#ifndef INCLUDE_H
#define INCLUDE_H

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <include.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef EXEC_TIME
    #define TIME if(1)
    #include <sys/time.h>
	struct timeval start, end;
	long elapsedTime;
#endif


/**
 * Determined at compile time based on ELF architecture
*/
#ifdef ARCH32
#define ELF_CLASS 1 
#else 
#define ELF_CLASS 2
#endif


#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#if DEBUG
    #define dprint(...) (printf(__VA_ARGS__))
#else
    #define dprint(...)
#endif


//path
/* A little useful strings for the construction of the absolute paths in the recovery of instrument information*/
#define file_path_number_suf_call   "/call/number.txt"
#define file_path_number_suf_ret    "/ret/number.txt"
#define dir_path_call_suf           "/call/"
#define dir_path_ret_suf            "/ret/"
#define node                        "/proc/kss_node"      /* Path of the node in /proc to communicate the activities to be performed at the kernel*/

extern char file_path_number_call[256];
extern char file_path_number_ret[256];
extern char dir_path_call[256];
extern char dir_path_ret[256] ;

void load_and_exec(unsigned char* elf, char **argv, char **env, size_t *stack,char *path_instr_info);


struct elf_info {
	ElfW(Ehdr) *ehdr;
	ElfW(Addr) entry_point;
	char *interp;
};

/*
 * Mapping
 */


#ifdef LOG_SYSTEM
    extern int id_user;
    extern char *input_file;    
#endif
#ifdef RAND_PERC
    extern int perc;
#endif

void map(unsigned char *data, struct elf_info *md, int is_interp, char *path_instr_info);

bool is_compatible_elf(const ElfW(Ehdr) *ehdr);
size_t compute_total_memory_size(const ElfW(Ehdr) *ehdr, const ElfW(Phdr) *phdr);
unsigned char *setup_memory(unsigned char *data, size_t total_to_map, ElfW(Phdr) *phdr, size_t *virtual_offset, ElfW(Ehdr) *ehdr, struct elf_info *md);
size_t map_segments(unsigned char *mapping, unsigned char *data, ElfW(Phdr) *phdr, size_t virtual_offset, size_t total_to_map, ElfW(Ehdr) *ehdr, struct elf_info *md);

/*
 * Stack creation and setup interface
 */
void synthetic_auxv(size_t *auxv);
void stack_setup(size_t *stack_base, int argc, char **argv, char **env, size_t *auxv,
		ElfW(Ehdr) *exe, ElfW(Ehdr) *interp);

/*
 * Custom flow control
 */

void jump(size_t dest, size_t *stack);

#endif
