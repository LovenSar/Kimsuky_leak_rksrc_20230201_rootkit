#ifndef UTIL_H
#define UTIL_H

#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>

#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>

#include "config.h"


/*
static char *strnstr(const char *haystack, const char *needle, size_t n)
{
    char *s = strstr(haystack, needle);
    if (s == NULL)
        return NULL;
    if (s - haystack + strlen(needle) <= n)
        return s;
    else
        return NULL;
}
*/
__attribute__((always_inline)) char *_strnstr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
				
			} while (sc != c);
			
			if (len > slen)
				return (NULL);
			
		} while (strncmp(s, find, len) != 0);
		
		s--;
	}
	return ((char *)s);
}

void *memmem(void *haystack, unsigned long haystack_size, void *needle, unsigned long needle_size )
{
    char *p;

    for (p = (char *)haystack; p <= (char *)(haystack - needle_size + haystack_size); p++ )
    {
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;
    }

    return NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
__attribute__((always_inline)) int _strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

__attribute__((always_inline)) const char *_strstri(const char* str, const char* subStr)
{
    int len = strlen(subStr);
    if(len == 0)
    {
       return NULL;
    }

    while(*str)
    {
        if(_strncasecmp(str, subStr, len) == 0)
        {
           return str;
        }
        ++str;
    }

    return NULL;
}


static int readline(char *buf,struct file *file)
{
	static char total[512];
	static int rest;			/// 剩下的字符数目

	char temp[128];
	int	len,i,cnt,count;
	
	cnt	= 0;
	for (i = 0;i < rest;i ++ ){
		if(total[i] == '\n'){	
			cnt ++;
			break;
		}
	}

	if(cnt == 0){				/// 信息不够 没有一个 '\n'
	   count = file->f_op->read(file, temp, sizeof(temp), &file->f_pos);
	   if(count == 0)
		  return 0;
	  
	   strncpy(total+rest,temp,count);
	   rest += count;
	}		
							
	len	= 0;
	while( (temp[len] = total[len]) ){
		len ++;
		if(total[len] == '\n')
			break;
	}
	temp[len]	= '\n';
				
	buf[0]='\n';
	strncpy(buf+1,temp,len+1);
	buf[len+2] = '\0';
	
	rest -= len+1;				/// 信息前移
	for (i = 0;i < rest ;i ++){
		total[i] = total[i+len+1];
	}

	return 1;
}


#define KALLSYMS_PATH		"/proc/kallsyms"
/// return, symbol addr
static void *_find_symbol(const char *func_name, char *_path)
{
        mm_segment_t old_fs;
        struct file *file = NULL;
	    char read_buf[500];
        const char *p;
		char tmp[20];
	    void *addr = 0;
        int i = 0;
		int len = 0;
	    char tmp_symbol_name[1024] = "T ";
		
        // 内核中fs指向用户数据段, 这里让指向内核数据段
        old_fs = get_fs();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        set_fs(get_ds());
#else
        set_fs(KERNEL_DS);
#endif
		
	    strcat(tmp_symbol_name, func_name);

	    len = strlen(tmp_symbol_name);

        file = filp_open(_path, O_RDONLY, 0);
        if (!file)
            return NULL;

        if (!file->f_op->read)
            return NULL;

        while( readline(read_buf ,file ) ){
              if((p = _strstri(read_buf, tmp_symbol_name)) != NULL) {
        /*
        NOTES: ' ' & '\t'
        c0123456 T sys_read
        e0654321 T cdrom_open    [cdrom]
        */
                 if( (*(p+len) != '\n') && (*(p+len) != '\t') )
                    continue;
				
                 while(*p--)
                      if(*p == '\n')
                         break;
                 i = 0;
                 while( (tmp[i++] = (*++ p) ) != ' ');
                 tmp[--i] = '\0';
                 addr = (void *)simple_strtoul(tmp, NULL, 16);
						
                 break;
              }
        }
		
        filp_close(file,NULL);
		
        set_fs(old_fs);

        return addr;
}

static void *lookup_kallsyms(const char *func_name, char *_path, int search_cnt)
{
	void *addr = 0;
	int i = 0;

	for (i = 0; i < search_cnt; i++) {
		addr = _find_symbol(func_name, _path);
		if (addr)
			break;
	}
			
	return addr;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static void *lookup_kallsyms(const char *func_name, char *_path, int search_cnt)
{
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
	
    register_kprobe(&kp);
	
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	
    unregister_kprobe(&kp);
#endif

	return (void *)kallsyms_lookup_name(func_name);
}
#endif


static void *get_symbol_address(const char *name)
{
	return lookup_kallsyms(name, KALLSYMS_PATH, 2);
}



__attribute__((always_inline)) static inline void _Write_cr0(unsigned long cr0) {
  //asm volatile("mov %0,%%cr0": "+r"(cr0), "+m"(__force_order));
  asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}

__attribute__((always_inline)) static inline void off_cr0(void)
{
#if defined(__i386__)	
	preempt_disable();
	barrier();
	_Write_cr0(read_cr0() & (~ 0x10000)); //enables memory writing by changing a register somewhere

#elif defined(__x86_64__)
	preempt_disable();
	barrier();
	_Write_cr0(read_cr0() & (~ 0x00010000)); //enables memory writing by changing a register somewhere
#endif
}

__attribute__((always_inline)) static inline void on_cr0(void)
{
#if defined(__i386__)	
// read somewhere it's terrible practice
	_Write_cr0(read_cr0() | 0x10000);
	barrier();
	preempt_enable();

#elif defined(__x86_64__)
// read somewhere it's terrible practice
	_Write_cr0(read_cr0() | 0x00010000);
	barrier();
	preempt_enable();
#endif
}
#define GPF_DISABLE  off_cr0();
// read somewhere it's terrible practice
#define GPF_ENABLE  on_cr0();



#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#ifndef set_memory_x_t
typedef typeof(set_memory_x) set_memory_x_t;
#endif
set_memory_x_t *ptr_mem_x = NULL;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25)
#ifndef ptr_lookup_address
typedef typeof(lookup_address) fn_lookup_address;
#endif
fn_lookup_address * ptr_lookup_address = NULL;
#endif

int init_util_func(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25)
	ptr_lookup_address = (fn_lookup_address *)get_symbol_address("lookup_address");
	if (!ptr_lookup_address) {
		return -1;
	}
#endif
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    ptr_mem_x = (set_memory_x_t *)get_sym_address("set_memory_x");
    if (!ptr_mem_x)
        return  -1;
#endif
	
	return 1;
}

// set_addr_rw
static void set_page_rw(unsigned long _addr)
{
    unsigned int level;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    struct page *pg;

    pgprot_t prot;
    pg = virt_to_page(_addr);
    prot.pgprot = VM_READ | VM_WRITE;
    change_page_attr(pg, 1, prot);
#else

    pte_t *pte = ptr_lookup_address(_addr, &level);
    if (pte->pte & ~ _PAGE_RW)
        pte->pte |= _PAGE_RW;
#endif
}

static void set_page_ro(unsigned long _addr)
{
    unsigned int level;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    struct page *pg;

    pgprot_t prot;
    pg = virt_to_page(_addr);
    prot.pgprot = VM_READ;
    change_page_attr(pg, 1, prot);
#else
    pte_t *pte = ptr_lookup_address(_addr, &level);

    pte->pte = pte->pte & ~_PAGE_RW;
#endif

}

static void set_page_x(unsigned long _addr)
{
    unsigned int level;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    struct page *pg;

    pgprot_t prot;
    pg = virt_to_page(_addr);
    prot.pgprot = VM_READ | VM_WRITE;
    change_page_attr(pg, 1, prot);
#else
    pte_t *pte = ptr_lookup_address(_addr, &level);

    if (pte->pte & ~ _PAGE_NX)
        pte->pte |= _PAGE_NX;
#endif

}






#endif
