/**
 * 工具函数头文件
 * 提供字符串处理、内存操作、内核符号查找等工具函数
 * 包含内核版本兼容性处理
 */

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
 * 字符串查找函数（已注释掉的原版本）
 * 在指定长度内查找子字符串
 */
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

/**
 * 优化的字符串查找函数
 * 在指定长度内查找子字符串，使用内联优化
 * @param s 源字符串
 * @param find 要查找的子字符串
 * @param slen 源字符串长度
 * @return 找到的位置指针，未找到返回NULL
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

/**
 * 内存块查找函数
 * 在指定大小的内存块中查找子内存块
 * @param haystack 源内存块
 * @param haystack_size 源内存块大小
 * @param needle 要查找的内存块
 * @param needle_size 要查找的内存块大小
 * @return 找到的位置指针，未找到返回NULL
 */
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

// 老版本内核的字符串比较函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
/**
 * 大小写不敏感的字符串比较函数
 * 比较指定长度的字符串，忽略大小写
 * @param s1 字符串1
 * @param s2 字符串2
 * @param n 比较长度
 * @return 比较结果
 */
__attribute__((always_inline)) int _strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

/**
 * 大小写不敏感的字符串查找函数
 * 在字符串中查找子字符串，忽略大小写
 * @param str 源字符串
 * @param subStr 要查找的子字符串
 * @return 找到的位置指针，未找到返回NULL
 */
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

/**
 * 从文件中读取一行数据
 * 支持跨读取操作的行缓冲
 * @param buf 输出缓冲区
 * @param file 文件指针
 * @return 成功返回1，失败返回0
 */
static int readline(char *buf,struct file *file)
{
	static char total[512];        // 静态缓冲区
	static int rest;		        // 剩余的字符数

	char temp[128];
	int	len,i,cnt,count;
	
	cnt	= 0;
	// 检查缓冲区中是否已有完整行
	for (i = 0;i < rest;i ++ ){
		if(total[i] == '\n'){	
			cnt ++;
			break;
		}
	}

	if(cnt == 0){				// 缓冲区中没有完整行
	   count = file->f_op->read(file, temp, sizeof(temp), &file->f_pos);
	   if(count == 0)
		  return 0;
	  
	   strncpy(total+rest,temp,count);
	   rest += count;
	}		
							
	len	= 0;
	// 提取一行数据
	while ( (temp[len] = total[len]) ){
		len ++;
		if(total[len] == '\n')
			break;
	}
	temp[len]	= '\n';
				
	buf[0]='\n';
	strncpy(buf+1,temp,len+1);
	buf[len+2] = '\0';
	
	rest -= len+1;				// 更新剩余字符数
	// 移动缓冲区数据
	for (i = 0;i < rest ;i++){
		total[i] = total[i+len+1];
	}

	return 1;
}

// kallsyms符号查找路径
#define KALLSYMS_PATH		"/proc/kallsyms"

/**
 * 查找内核符号地址
 * 通过解析/proc/kallsyms文件获取函数地址
 * @param func_name 函数名称
 * @param _path kallsyms文件路径
 * @return 函数地址，未找到返回0
 */
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
		
        // 保存内核fs指针，切换到内核数据段
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

        // 逐行读取并解析
        while( readline(read_buf ,file ) ){
              if((p = _strstri(read_buf, tmp_symbol_name)) != NULL) {
        /*
        NOTES: ' ' & '\t'
        c0123456 T sys_read
        e0654321 T cdrom_open    [cdrom]
        */
                 if( (*(p+len) != '\n') && (*(p+len) != '\t') )
                    continue;
				
                 // 解析地址
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
		
        // 恢复fs指针
        set_fs(old_fs);

        return addr;
}

/**
 * 多次尝试查找内核符号
 * @param func_name 函数名称
 * @param _path kallsyms文件路径
 * @param search_cnt 搜索次数
 * @return 函数地址，未找到返回0
 */
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

// 新版本内核使用kprobes查找符号
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

/**
 * 使用kprobes查找内核符号
 * 适用于新版本内核
 * @param func_name 函数名称
 * @param _path 未使用
 * @param search_cnt 未使用
 * @return 函数地址
 */
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

/**
 * 获取符号地址的统一接口
 * @param name 符号名称
 * @return 符号地址
 */
static void *get_symbol_address(const char *name)
{
	return lookup_kallsyms(name, KALLSYMS_PATH, 2);
}

// 页保护操作函数
/**
 * 写入CR0寄存器
 * 用于控制页保护
 */
__attribute__((always_inline)) static inline void _Write_cr0(unsigned long cr0) {
  //asm volatile("mov %0,%%cr0": "+r"(cr0), "+m"(__force_order));
  asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}

/**
 * 禁用CR0页保护
 * 允许写入只读内存页
 */
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

/**
 * 启用CR0页保护
 * 恢复内存页保护
 */
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

// 页保护宏定义
#define GPF_DISABLE  off_cr0();
#define GPF_ENABLE  on_cr0();

// 新版本内核的内存权限设置函数指针
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#ifndef set_memory_x_t
typedef int (*set_memory_x_t)(unsigned long addr, int numpages);
#endif
extern set_memory_x_t *ptr_mem_x;
#endif

// 老版本内核的地址查找函数指针
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25)
#ifndef ptr_lookup_address
typedef typeof(lookup_address) fn_lookup_address;
#endif
fn_lookup_address * ptr_lookup_address = NULL;
#endif

/**
 * 初始化工具函数
 * 获取必要的内核函数地址
 * @return 成功返回1，失败返回-1
 */
int init_util_func(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25)
	// 获取lookup_address函数地址
	ptr_lookup_address = (fn_lookup_address *)get_symbol_address("lookup_address");
	if (!ptr_lookup_address) {
		return -1;
	}
#endif
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    // 获取set_memory_x函数地址
    ptr_mem_x = (set_memory_x_t *)get_symbol_address("set_memory_x");
    if (!ptr_mem_x)
        return  -1;
#endif
	
	return 1;
}

/**
 * 设置内存页为可读写
 * @param _addr 内存地址
 */
static void set_page_rw(unsigned long _addr)
{
    unsigned int level;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    // 老版本内核使用change_page_attr
    struct page *pg;
    pgprot_t prot;
    pg = virt_to_page(_addr);
    prot.pgprot = VM_READ | VM_WRITE;
    change_page_attr(pg, 1, prot);
#else
    // 新版本内核使用PTE操作
    pte_t *pte = ptr_lookup_address(_addr, &level);
    if (pte->pte & ~ _PAGE_RW)
        pte->pte |= _PAGE_RW;
#endif
}

/**
 * 设置内存页为只读
 * @param _addr 内存地址
 */
static void set_page_ro(unsigned long _addr)
{
    unsigned int level;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    // 老版本内核
    struct page *pg;
    pgprot_t prot;
    pg = virt_to_page(_addr);
    prot.pgprot = VM_READ;
    change_page_attr(pg, 1, prot);
#else
    // 新版本内核
    pte_t *pte = ptr_lookup_address(_addr, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
#endif
}

/**
 * 设置内存页为可执行
 * @param _addr 内存地址
 */
static void set_page_x(unsigned long _addr)
{
    unsigned int level;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
    // 老版本内核
    struct page *pg;
    pgprot_t prot;
    pg = virt_to_page(_addr);
    prot.pgprot = VM_READ | VM_WRITE;
    change_page_attr(pg, 1, prot);
#else
    // 新版本内核
    pte_t *pte = ptr_lookup_address(_addr, &level);

    if (pte->pte & ~ _PAGE_NX)
        pte->pte |= _PAGE_NX;
#endif
}

#endif
