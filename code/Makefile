LKM_PATH := ./LKM
LOADER_PATH := ./Loader
LOADER_EXE := $(LOADER_PATH)/Kss_loader
COMMON_FLAGS := -I ./Loader/include/ -Wall -Werror -pedantic -std=gnu99 

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


kernel: 
	make -I $(LKM_PATH)/includes  -C $(KDIR) M=$(PWD) modules
loader:
	gcc $(COMMON_FLAGS) $(LOADER_SOURCE_FILES) -o $(LOADER_EXE)

all:
	
	rm -f $(LOADER_EXE)
	kernel
	loader
	

clean clear:
	rm -f $(LOADER_EXE)
	make -I $(LKM_PATH)/includes -C $(KDIR) M=$(PWD) clean


install:
	insmod kss_module.ko

remove:
	rmmod kss_module

