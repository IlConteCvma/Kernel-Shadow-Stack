obj-m := kss_module.o
kss_module-y :=  driver-core.o logging.o utils.o kss_struct_logic.o ht_logic.o hooks.o


KDIR ?= /lib/modules/$(shell uname -r)/build


all:
	
	rm -f ./loader/elfloader/elfloader-master/reflect
	gcc -I ./loader/elfloader/elfloader-master/include/ -Wall -Werror -pedantic -std=gnu99 --static-pie ./loader/elfloader/elfloader-master/src/main.c ./loader/elfloader/elfloader-master/src/exec.c ./loader/elfloader/elfloader-master/src/map_elf.c ./loader/elfloader/elfloader-master/src/stack_setup.c ./loader/elfloader/elfloader-master/src/jump.c -o ./loader/elfloader/elfloader-master/reflect
	make -C $(KDIR) M=$(PWD) modules 

clean clear:
	rm -f ./loader/elfloader/elfloader-master/reflect
	make -C $(KDIR) M=$(PWD) clean


install:
	insmod kss_module.ko

remove:
	rmmod kss_module
	