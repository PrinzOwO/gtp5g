PWD := $(shell pwd) 
KVERSION := $(shell uname -r)
INCLUDE_DIR = /usr/src/linux-headers-$(KVERSION)/

CONFIG_MODULE_SIG=n
MODULE_NAME = gtp5g

MY_CFLAGS += -g -DDEBUG
EXTRA_CFLAGS += -Wno-misleading-indentation -Wuninitialized
CC += ${MY_CFLAGS}

obj-m := $(MODULE_NAME).o

all:
	make -C $(INCLUDE_DIR) M=$(PWD) modules
clean:
	make -C $(INCLUDE_DIR) M=$(PWD) clean
 
install:
	modprobe udp_tunnel
	cp $(MODULE_NAME).ko /lib/modules/`uname -r`/kernel/drivers/net
	depmod -a
	modprobe $(MODULE_NAME)
	echo "gtp5g" >> /etc/modules

uninstall:
	rmmod $(MODULE_NAME)
	rm -f /lib/modules/`uname -r`/kernel/drivers/net/$(MODULE_NAME).ko
	depmod -a
	sed -zi "s/gtp5g\n//g" /etc/modules
