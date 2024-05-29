#include "includes/dirver-core.h"
#include "includes/hooks.h"


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

/*
 * Kernel Probe to obtain the address of the Kallsyms_lookup_Name () function.
 * This function allows you to recover the addresses of events managers
 * of interest in order to check if the current version of the kernel can
 * be used.
 */
struct kprobe kp_kallsyms_lookup_name = {
    .symbol_name = kallsyms_lookup_name_func
};
#endif

struct kprobe kp_kernel_clone = {
    .symbol_name = kernel_clone_func,
    .pre_handler = handler_kernel_clone
};

/*
 * Kernel Probe to intercept the allocation of safety metadata.When
 * new threads will be generated, it occurs if there is a need to allocate
 * The safety metadata before the request for
 * simulate calls and ret.
 */
struct kprobe kp_finish_task_switch = {
    .symbol_name = finish_task_switch_func,
    .pre_handler = handler_finish_task_switch
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
struct kprobe kp_finish_task_switch_cold = {
    .symbol_name = finish_task_switch_cold_func,
    .pre_handler = handler_finish_task_switch
};
#endif

/*
 * Kernel Probe to intercept the execution of the Do_exit () function.In the
 * DO_EXIT () function will be released allocated safety metadata.
 */
struct kprobe kp_do_exit = {
    .symbol_name = do_exit_func,
    .pre_handler = hook_do_exit
};


/**
 * install_kprobes - KPROBES installation necessary to correctly use security architecture.
 * The hook on the do_exit () allows you to dealocate the data structures used in architecture while the hooks on the
 * Finish_task_Switch () allow you to allocar them and initialize them.The hook on the kernel_clone () allows you to use
 * correctly the reference counter in order to dealut the data structures shared by the threads of the same
 * process and to be dismantled the kernel module correctly.
 *
 * @return: return 1 if all the kProbe have been successfully allocated;Otherwise, it returns the value 0.
 */
int install_kprobes(void) {
    int ret;


    /* Install the proe kernels on the finish_task_switch() */
    ret = register_kprobe(&kp_finish_task_switch);

    if(ret < 0) {
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE #1 on 'finish_task_switch()'\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

     #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    ret = register_kprobe(&kp_finish_task_switch_cold);

    if(ret < 0) {
        unregister_kprobe(&kp_finish_task_switch);
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE #2 on 'finish_task_switch()' %d \n",
        MOD_NAME,
        current->pid,
        ret);
        return 0;
    }
    #endif

    /* Install the KPROBE on the do_exit()                 */
    ret = register_kprobe(&kp_do_exit);

    if(ret < 0) {
        unregister_kprobe(&kp_finish_task_switch);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        unregister_kprobe(&kp_finish_task_switch_cold);
        #endif
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE on the 'do_exit()'\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

    dprint_info_test("%s: [MODULE INFO TEST] [%d] Do exit register pointer %lx\n",
            MOD_NAME,
            current->pid,
            (unsigned long) &kp_do_exit);

    /* Install the KPROBE on the kernel_clone()                 */
    ret = register_kprobe(&kp_kernel_clone);

    if(ret < 0) {
        unregister_kprobe(&kp_finish_task_switch);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        unregister_kprobe(&kp_finish_task_switch_cold);
        #endif
        unregister_kprobe(&kp_do_exit);
        pr_err("%s: [ERROR MODULE INIT] [INSTALLATION KPROBE] [%d] Error in the recording of the KPROBE on the 'kernel_clone()'\n",
        MOD_NAME,
        current->pid);
        return 0;
    }

    pr_info("%s: [MODULE INIT] [INSTALLATION KPROBE] [%d] Recording of the hooks successfully taken place\n",
    MOD_NAME,
    current->pid);

    return 1;
}

void remove_probes(void){
    unregister_kprobe(&kp_kernel_clone);
    unregister_kprobe(&kp_finish_task_switch);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    unregister_kprobe(&kp_finish_task_switch_cold);
    #endif

    dprint_info_test("%s: [MODULE INFO TEST] [%d] Do exit UNregister pointer %lx\n",
    MOD_NAME,
    current->pid,
    (unsigned long) &kp_do_exit);

    unregister_kprobe(&kp_do_exit);

    pr_info("%s: [MODULE EXIT] [%d] The prob kernels were successfully removed\n",
    MOD_NAME,
    current->pid);

}