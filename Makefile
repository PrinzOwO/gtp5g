PWD := $(shell pwd) 
KVERSION := $(shell uname -r)
INCLUDE_DIR = /usr/src/linux-headers-$(KVERSION)/

CONFIG_MODULE_SIG=n
MODULE_NAME = gtp5g
obj-m := $(MODULE_NAME).o

all:
	make -C $(INCLUDE_DIR) M=$(PWD) modules
clean:
	make -C $(INCLUDE_DIR) M=$(PWD) clean
 
install:
	modprobe udp_tunnel
	insmod $(MODULE_NAME).ko
uninstall:
	rmmod $(MODULE_NAME)
