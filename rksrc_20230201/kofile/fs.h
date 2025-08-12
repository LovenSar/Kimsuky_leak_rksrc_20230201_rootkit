/**
 * 文件系统操作头文件
 * 提供内核空间的文件操作接口
 * 支持多种内核版本的兼容性处理
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#include <linux/umh.h>
#else
#include <linux/kmod.h>
#endif
#include <linux/namei.h>

// 文件操作函数声明
int _kfile_stat(const char *name, struct kstat *stat);
struct file *_kopen_file(const char *name);

ssize_t _kwrite_file(struct file *filp, const void *ptr, size_t len, loff_t *offset);
ssize_t _kread_file(struct file *filp, void *ptr, size_t len, loff_t *offset);

int _kclose_file(struct file *filp);
int fs_file_rm(char *name);

/**
 * 获取文件状态信息
 * 兼容不同内核版本的文件状态获取方式
 * @param name 文件路径
 * @param stat 状态信息结构体
 * @return 成功返回0，失败返回错误码
 */
int _kfile_stat(const char *name, struct kstat *stat) {
   // struct path path;
#ifdef get_fs
    mm_segment_t security_old_fs;
#endif
    int rc = -EINVAL;
    if (!stat || !name)
        return rc;

#ifdef get_fs
    // 保存并设置fs指针（老版本内核）
    security_old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif
/*
    // 新版本内核的文件状态获取方式（已注释）
    rc = kern_path(name, LOOKUP_FOLLOW, &path);
    if (rc)
        goto out;

    rc = vfs_getattr(&path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    path_put(&path);
*/
	// 函数声明注释
	// int vfs_getattr(struct path *path, struct kstat *stat)
	// int vfs_stat(char __user *name, struct kstat *stat)

out:
#ifdef get_fs
    // 恢复fs指针
    set_fs(security_old_fs);
#endif

    return rc;
}

/**
 * 打开文件
 * 在内核空间打开或创建文件
 * @param name 文件路径
 * @return 文件结构体指针，失败返回NULL
 */
struct file *_kopen_file(const char *name) {
    struct file *filp;

    if (!name) {
        return NULL;
    }

    /** I won't let it go. Thanks. (kernel joke) */
    // 以创建、追加、读写、大文件模式打开文件，权限为600
    filp = filp_open(name, O_CREAT|O_APPEND|O_RDWR|O_LARGEFILE, 0600);
    if (IS_ERR(filp)) {
        return NULL;
    }
    return filp;
}

/**
 * 写入文件
 * 向文件写入数据，支持多种内核版本
 * @param filp 文件结构体指针
 * @param ptr 数据指针
 * @param len 数据长度
 * @param offset 文件偏移量指针
 * @return 写入的字节数，失败返回错误码
 */
ssize_t _kwrite_file(struct file *filp, const void *ptr, size_t len, loff_t *offset)
{
    if (!filp) {
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    // 新版本内核使用kernel_write
    return kernel_write(filp, ptr, len, offset);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(3, 9, 0)
    // 3.9+内核版本
    return kernel_write(filp, (const char*)ptr, len, *offset);
	
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
    // 老版本内核使用set_fs + vfs_write
	mm_segment_t old_fs;
	ssize_t res;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_write(filp, (const char __user *)ptr, len, offset);
	set_fs(old_fs);
	
	return res;
#endif

}

/**
 * 读取文件
 * 从文件读取数据，支持多种内核版本
 * @param filp 文件结构体指针
 * @param ptr 数据缓冲区指针
 * @param len 要读取的长度
 * @param offset 文件偏移量指针
 * @return 读取的字节数，失败返回错误码
 */
ssize_t _kread_file(struct file *filp, void *ptr, size_t len, loff_t *offset)
{
    if (!filp) {
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    // 新版本内核使用kernel_read
    return kernel_read(filp, ptr, len, offset);
#else
    // 老版本内核
    return kernel_read(filp, *offset, (char*)ptr, len);
#endif
}

/**
 * 关闭文件
 * 关闭内核空间打开的文件
 * @param filp 文件结构体指针
 * @return 成功返回0，失败返回错误码
 */
int _kclose_file(struct file *filp) {
    if (!filp)
        return -EINVAL;

    return filp_close(filp, NULL);
}

/**
 * 删除文件
 * 通过用户空间命令删除文件（已注释掉）
 * @param name 要删除的文件路径
 * @return 成功返回0，失败返回-1
 */
int fs_file_rm(char *name) {
    static char *rm[] = {"/bin/rm", "-f", NULL, NULL};
    struct subprocess_info *info;
    int ret = -1;
    if (!name)
        return -EINVAL;

    rm[2] = name;
/*
    // 通过call_usermodehelper执行rm命令（已注释）
    if ((info = call_usermodehelper_setup(rm[0], rm, NULL, GFP_KERNEL, NULL, NULL, NULL)))
	{
        ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
        //if (ret)
            //prerr("Error removing %s\n", name);
    }
	*/
    return ret;
}
