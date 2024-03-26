obj-m := kss-module.o
kss-module-y :=  driver-core.o logging.o utils.o kss_struct_logic.o ht_logic.o hooks.o


KDIR ?= /lib/modules/$(shell uname -r)/build


all:
	make -C $(KDIR) M=$(PWD) modules 

clean:
	make -C $(KDIR) M=$(PWD) clean