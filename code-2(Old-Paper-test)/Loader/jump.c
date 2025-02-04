#include <stdlib.h>
#include "include/include.h"


#ifndef ARCH32
#define JUMP_TO(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"movq %[stack], %%rsp\n" \
			"xor %%rdx, %%rdx\n" \
			"jmp *%[entry]"  \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "rdx", "memory" \
			)
#else
#define JUMP_TO(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"movl %[stack], %%esp\n"  \
			"xor %%edx, %%edx\n"  \
			"jmp *%[entry]" \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "edx", "memory" \
			)
#endif

#ifdef EXEC_TIME
	#include <stdio.h>
	#include <unistd.h>
#endif

inline void __attribute ((noreturn)) jump(size_t dest, size_t *stack)
{
#ifdef EXEC_TIME
	gettimeofday(&end, NULL);
	printf("Elapsed time before jump point: %lds %ldus\n", end.tv_sec - start.tv_sec, (end.tv_usec - start.tv_usec));
#endif
	JUMP_TO(dest, stack);

	abort();
}
