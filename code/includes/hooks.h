#ifndef HOOKS_H
#define HOOKS_H

/* Names of the kernel functions on which to install the Hooks                                                               */
#define do_exit_func                 "do_exit"
#define kallsyms_lookup_name_func    "kallsyms_lookup_name"
#define finish_task_switch_func      "finish_task_switch.isra.0"
#define finish_task_switch_cold_func "finish_task_switch.isra.0.cold"
#define kernel_clone_func            "kernel_clone"




#endif