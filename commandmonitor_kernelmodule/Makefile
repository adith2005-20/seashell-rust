# Target object file name must match the C file name (without extension)
obj-m := cmd_monitor.o

# Path to the kernel source/build directory
# Uses currently running kernel's build path by default
KDIR ?= /lib/modules/$(shell uname -r)/build

# Current working directory
PWD := $(shell pwd)

# Default target: Build the kernel module(s)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Target to clean up build files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Optional: Target to install the module
# Use 'sudo make install'
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# Optional: Target to uninstall the module
# Use 'sudo make uninstall' (adjust path if needed)
uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/cmd_monitor.ko
	depmod -a

.PHONY: all clean install uninstall
