#ifndef REFLECT_H
#define REFLECT_H

#include <elf.h>
#include <link.h>
#include <stdbool.h>

#include "conf.h"

/*
 * Config
 */
#ifndef REFLECT_HAVE_ASM
/* Determined at configure time. If assembly was not detected, you can add
 * support by porting the JUMP_WITH_STACK macro to arch/@HOST_OS@/@HOST_CPU@/arch_jump.h */
#define REFLECT_HAVE_ASM @HAVE_ASM@
#endif

/*
 * High-level interface
 */


/* No equivalent for using a custom stack without using custom assembly */
void reflect_execves(const unsigned char *elf, char **argv, char **env, size_t *stack);


void reflect_execv(const unsigned char *elf, char **argv);
void reflect_execve(const unsigned char *elf, char **argv, char **env);

/*
 * Force using memfd_create/execveat fallback
 */
void reflect_mfd_execv(const unsigned char *elf, char **argv);
void reflect_mfd_execve(const unsigned char *elf, char **argv, char **env);


/*
 * ELF mapping interface
 */
struct mapped_elf {
	ElfW(Ehdr) *ehdr;
	ElfW(Addr) entry_point;
	char *interp;
};

#ifdef LOG_SYSTEM
#ifdef RAND_PERC
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info, char *input_file, int id_user, int perc);
#else
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info, char *input_file, int id_user);
#endif
#else
#ifdef RAND_PERC
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info, int perc);
#else
void map_elf(const unsigned char *data, struct mapped_elf *obj, int is_interp, char *path_instr_info);
#endif
#endif

bool is_compatible_elf(const ElfW(Ehdr) *ehdr);

/*
 * Stack creation and setup interface
 */
void synthetic_auxv(size_t *auxv);
void modify_auxv(size_t *auxv, ElfW(Ehdr) *exe, ElfW(Ehdr) *interp);
void stack_setup(size_t *stack_base, int argc, char **argv, char **env, size_t *auxv,
		ElfW(Ehdr) *exe, ElfW(Ehdr) *interp);

/*
 * Custom flow control
 */

void jump_with_stack(size_t dest, size_t *stack);

#endif
