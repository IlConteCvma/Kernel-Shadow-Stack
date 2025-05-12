LKM_PATH := ./LKM
LOADER_PATH := ./Loader
LOADER_EXE := $(LOADER_PATH)/Kss_loader
COMMON_FLAGS = -I ./Loader/include/ -Wall -Werror -pedantic -std=gnu99
LOADER_EXTRA_FLAGS =
KSS_EXTRA_CFLAGS =

# default def
CFU := 1

obj-m := kss_module.o
kss_module-y :=  	$(LKM_PATH)/driver-core.o \
					$(LKM_PATH)/logging.o \
					$(LKM_PATH)/utils.o \
                 	$(LKM_PATH)/kss_struct_logic.o \
					$(LKM_PATH)/ht_logic.o \
					$(LKM_PATH)/hooks.o

KDIR ?= /lib/modules/$(shell uname -r)/build

LOADER_SOURCE_FILES := \
	$(LOADER_PATH)/main.c \
	$(LOADER_PATH)/instrumentation.c \
	$(LOADER_PATH)/loader.c \
	$(LOADER_PATH)/mapper.c \
	$(LOADER_PATH)/stack_setup.c \
	$(LOADER_PATH)/jump.c \

# ------ POSSIBLE CONFIGURATION ------

# loader and kss common configuration
ifeq ($(DEBUG),1)
   LOADER_EXTRA_FLAGS+=-g -DDEBUG
   KSS_EXTRA_CFLAGS+=-DDEBUG
endif
ifeq ($(DEBUG),2)
   LOADER_EXTRA_FLAGS+=-g -DDEBUG 
   KSS_EXTRA_CFLAGS+=-DDEBUG_V
endif
ifdef LOG
   LOADER_EXTRA_FLAGS+=-DLOG_SYSTEM
   KSS_EXTRA_CFLAGS+=-DLOG_SYSTEM
endif

# loader configuration
ifdef WITH_IN
   LOADER_EXTRA_FLAGS+=-DWITH_IN
endif

ifeq ($(RANDOM),1) # random subset
   LOADER_EXTRA_FLAGS+=-DRANDOM_SUBSET_FUNC
endif
ifeq ($(RANDOM),2) # random subset with rand percetage
   LOADER_EXTRA_FLAGS+=-DRANDOM_SUBSET_FUNC -DRAND_PERC
endif

# kss configuration
# copy_from_user mode
ifeq ($(CFU),1) 
   KSS_EXTRA_CFLAGS+=-DSINGLE_ADDRESS_ONE_COPY_FROM_USER
endif
ifeq ($(CFU),2) 
   KSS_EXTRA_CFLAGS+=-DSINGLE_ADDRESS
endif
ifeq ($(CFU),3) 
   KSS_EXTRA_CFLAGS+=-DBLOCK_ADDRESS
endif
ifeq ($(CFU),4) 
   KSS_EXTRA_CFLAGS+=-DMIX_ADDRESS
endif

#other conf
ifdef KILL_PROCESS # kill process if stack mismatch
   KSS_EXTRA_CFLAGS+=-DKILL_PROCESS
endif
ifdef KILL_PROCESS_CALL #if kss get a no call instruction to monitored adress
   KSS_EXTRA_CFLAGS+=-DKILL_PROCESS_NO_CALL
endif
ifdef GET_HOOKS_STATS #if kss get a no call instruction to monitored adress
   KSS_EXTRA_CFLAGS+=-DGET_HOOKS_STATS
endif



all:
	rm -f $(LOADER_EXE)
	$(MAKE) kernel
	$(MAKE) loader

kernel: 
	make -I $(LKM_PATH)/includes  -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="$(KSS_EXTRA_CFLAGS)"

loader:
	gcc $(COMMON_FLAGS) $(LOADER_EXTRA_FLAGS) $(LOADER_SOURCE_FILES) -o $(LOADER_EXE)


#clean clear:
clean:
	rm -f $(LOADER_EXE)
	make -I $(LKM_PATH)/includes -C $(KDIR) M=$(PWD) clean


install:
	insmod kss_module.ko

remove:
	rmmod kss_module

# ----- TARGET SHORTCUT -----

logging:
	make all LOG=1

SAOCFU: # SINGLE_ADDRESS_ONE_COPY_FROM_USER
	make kernel CFU=1
SA:	#SINGLE_ADDRESS
	make kernel CFU=2
BA: #BLOCK_ADDRESS
	make kernel CFU=3
MA: #MIX_ADDRESS
	make kernel CFU=4
