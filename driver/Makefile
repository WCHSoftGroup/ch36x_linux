ifeq ($(KERNELRELEASE), )
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR)  M=$(PWD)  
clean:
	rm -rf *.mk .tmp_versions Module.symvers *.mod.c *.o *.ko .*.cmd Module.markers modules.order *.mod *.a
load:
	insmod ch36x.ko
unload:
	rmmod ch36x
install: default
	insmod ch36x.ko
	mkdir -p /lib/modules/$(shell uname -r)/kernel/drivers/misc/
	cp -f ./ch36x.ko /lib/modules/$(shell uname -r)/kernel/drivers/misc/
	depmod -a
uninstall:
	rmmod ch36x.ko
	rm -rf /lib/modules/$(shell uname -r)/kernel/drivers/misc/ch36x.ko
	depmod -a
else
	obj-m := ch36x.o
endif
