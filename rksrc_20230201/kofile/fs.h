#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#include <linux/umh.h>
#else
#include <linux/kmod.h>
#endif
#include <linux/namei.h>


int _kfile_stat(const char *name, struct kstat *stat);
struct file *_kopen_file(const char *name);

ssize_t _kwrite_file(struct file *filp, const void *ptr, size_t len, loff_t *offset);
ssize_t _kread_file(struct file *filp, void *ptr, size_t len, loff_t *offset);


int _kclose_file(struct file *filp);
int fs_file_rm(char *name);


int _kfile_stat(const char *name, struct kstat *stat) {
   // struct path path;
#ifdef get_fs
    mm_segment_t security_old_fs;
#endif
    int rc = -EINVAL;
    if (!stat || !name)
        return rc;

#ifdef get_fs
    security_old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif
/*
    rc = kern_path(name, LOOKUP_FOLLOW, &path);
    if (rc)
        goto out;

    rc = vfs_getattr(&path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    path_put(&path);
*/
	// int vfs_getattr(struct path *path, struct kstat *stat)
	// int vfs_stat(char __user *name, struct kstat *stat)

out:
#ifdef get_fs
    set_fs(security_old_fs);
#endif

    return rc;
}

struct file *_kopen_file(const char *name) {
    struct file *filp;

    if (!name) {
        return NULL;
    }

    /** I won't let it go. Thanks. (kernel joke) */
    filp = filp_open(name, O_CREAT|O_APPEND|O_RDWR|O_LARGEFILE, 0600);
    if (IS_ERR(filp)) {
        return NULL;
    }
    return filp;
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
ssize_t _kwrite_file(struct file *filp, const void *ptr, size_t len, loff_t *offset)
//#else
//ssize_t _kwrite_file(struct file *filp, const char *ptr, size_t len, loff_t offset)
//#endif
{
    if (!filp) {
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    return kernel_write(filp, ptr, len, offset);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(3, 9, 0)
    return kernel_write(filp, (const char*)ptr, len, *offset);
	
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
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

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
ssize_t _kread_file(struct file *filp, void *ptr, size_t len, loff_t *offset)
//#else
//int _kread_file(struct file *filp, loff_t offset, char *ptr, unsigned long len)
//#endif
{
    if (!filp) {
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    return kernel_read(filp, ptr, len, offset);
#else
    return kernel_read(filp, *offset, (char*)ptr, len);
#endif
}

int _kclose_file(struct file *filp) {
    if (!filp)
        return -EINVAL;

    return filp_close(filp, NULL);
}

int fs_file_rm(char *name) {
    static char *rm[] = {"/bin/rm", "-f", NULL, NULL};
    struct subprocess_info *info;
    int ret = -1;
    if (!name)
        return -EINVAL;

    rm[2] = name;
/*
    if ((info = call_usermodehelper_setup(rm[0], rm, NULL, GFP_KERNEL, NULL, NULL, NULL)))
	{
        ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
        //if (ret)
            //prerr("Error removing %s\n", name);
    }
	*/
    return ret;
}
