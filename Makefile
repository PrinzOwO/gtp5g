PWD := $(shell pwd) 
KVERSION=$(shell uname -r)
INCLUDE_DIR = /usr/src/linux-headers-$(KVERSION)/

CONFIG_MODULE_SIG=n
MODULE_NAME = gtp5g

MY_CFLAGS += -g -DDEBUG
EXTRA_CFLAGS += -Wno-misleading-indentation -Wuninitialized
CC += ${MY_CFLAGS}

obj-m := $(MODULE_NAME).o

#
# return 'yes' or 'no' if this is an Ubuntu kernel that supports the additional argument
#
KVERSION_UBUNTU := $(shell uname -r | awk -F'-' '{if ($$2 >= 109) {print "yes"} else {print "no"}}')

KMAJMIN=$(grep -o '[0-9][0-9][0-9][0-9]*' /usr/include/linux/version.h)

##
## Handle specific version of Ubuntu modified kernels as well as generic 4.19.93 and above
## 4.19.93 == (4 << 16) + (19 << 8) + 93 == 267101

UPDATE_PMTU_BOOL := $(if KVERSION_UBUNTU=='yes', 1, $(if $KMAJMIN >= 267101, 1, 0))

#CFLAGS-y := -DUPDATE_PMTU_BOOL="$(UPDATE_PMTU_BOOL)"
ccflags-y := -DUPDATE_PMTU_BOOL="$(UPDATE_PMTU_BOOL)"

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
