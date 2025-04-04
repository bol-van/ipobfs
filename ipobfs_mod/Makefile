obj-m += ipobfs.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
KERNELRELEASE ?= $(shell uname -r)
PWD := $(shell pwd)
DEPMOD ?= depmod
STRIP ?= strip

all:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

mod-install:
	$(STRIP) --strip-debug *.ko
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	$(DEPMOD) -a $(KERNELRELEASE)

install : mod-install
