LKM_PATH := ./LKM
LOADER_PATH : = ./Loader
LOADER_EXE := $(LOADER_PATH)/Kss_loader
COMMON_FLAGS := -I ./Loader/include/ -Wall -Werror -pedantic -std=gnu99 

obj-m := $(LKM_PATH)/kss_module.o
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


all:
	
	rm -f $(LOADER_EXE)
	gcc $(COMMON_FLAGS) $(LOADER_SOURCE_FILES) -o $(LOADER_EXE)
	make -C $(KDIR) M=$(PWD) modules 

clean clear:
	rm -f $(LOADER_EXE)
	make -C $(KDIR) M=$(PWD) clean


install:
	insmod kss_module.ko

remove:
	rmmod kss_module

