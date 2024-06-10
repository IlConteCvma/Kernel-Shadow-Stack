#ifndef DRIVERCORE_H
#define DRIVERCORE_H

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <asm/trapnr.h>
#include <asm/desc.h>
#include <linux/sched/mm.h>
#include <linux/file.h>
#include <linux/string.h>
#include <asm/syscall.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/ioctl.h>


#include <linux/delay.h>

#include "module-defines.h"

typedef void (*exc_invalid_op_t) (struct pt_regs *regs);
typedef void (*sysvec_spurious_apic_interrupt_t) (struct pt_regs *regs);
typedef void (*do_group_exit_t)(int code);

extern do_group_exit_t do_group_exit_addr; //in driver-core.c
// Global variables

/* Takes into account the number of threads that are inside the architecture and which are still running              */
extern int num_threads;
extern exc_invalid_op_t exc_invalid_op; 
extern sysvec_spurious_apic_interrupt_t sysvec_spurious_apic_interrupt; 

#ifdef LOG_SYSTEM
/* The location in the System file and the format of log files produced by the monitoring system                       */
#define log_path_format  "/home/cap/%s_%d_%d_log.txt"
#define user_stack_path_format  "/home/cap/%s_%d_%d_user_stack.data"

/* List of strings containing the event format for the various types of events supported by architecture     */
#define no_call_format  "[NO CALL] :Address RETURN = 0x%px\tAddress di ritorno = 0x%px\n"
#define call_format     "[CALL]    :Function Target  = 0x%px\tAddress di ritorno = 0x%px\n"
#define ret_ii_format   "[RET II]  :Address RETURN = 0x%px\tAddress di ritorno = 0x%px\n"
#define ret_ni_format   "[RET NI]  :Address RETURN = 0x%px\tAddress di ritorno = 0x%px\n"
#define ret_suc_format  "[RET SUC] :Address ATTESO = 0x%px\tAddress EFFETTIVO  = 0x%px\tAddress RETURN = 0x%px\n"

/* Dimensions of the strings to write in the log file after recovering the event data                     */
extern int size_no_suc ; //in driver-core.c
extern int size_suc    ; //in driver-core.c
#endif //LOG_SYSTEM


/*
 * The 'Absolute_path_elf_loader' variable contains the name of the executable of our Elf Loader.This information is
 * At the basis of the process identification mechanism.To understand if the events have been generated
 * The name of the executable of which the process in execution with that of the Loader is intentionally compared
 * Elf.In the event of a match, we can assume that the events have been generated on purpose, and therefore, that it is necessary
 * perform the logic of security architecture and not the logic of the default management of the events present in
 * Kernel Linux.
 */
#define absolute_path_elf_loader  "Kss_loader"

#endif