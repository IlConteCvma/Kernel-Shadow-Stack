obj-m := kss_module.o
my_module-objs :=  driver-core.o  

KDIR ?= /lib/modules/$(shell uname -r)/build


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean