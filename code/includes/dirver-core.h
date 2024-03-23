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


#include "includes/module-defines.h"
#include "includes/utils.h"
#include "includes/kss_struct.h"
#include "includes/workqueue.h"


// Global variables

/* Takes into account the number of threads that are inside the architecture and which are still running              */
int num_threads = 0;

/*
 * The 'Absolute_path_elf_loader' variable contains the name of the executable of our Elf Loader.This information is
 * At the basis of the process identification mechanism.To understand if the events have been generated
 * The name of the executable of which the process in execution with that of the Loader is intentionally compared
 * Elf.In the event of a match, we can assume that the events have been generated on purpose, and therefore, that it is necessary
 * perform the logic of security architecture and not the logic of the default management of the events present in
 * Kernel Linux.
 */
const char *absolute_path_elf_loader = "reflect";





