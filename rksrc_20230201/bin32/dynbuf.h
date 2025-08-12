/*
 *
 */
#ifndef __DYNBUF_H__
#define __DYNBUF_H__

//#define DEBUG

#include <sys/types.h>

#ifndef IOBUF_MIN_SIZE
#define IOBUF_MIN_SIZE 2048
#endif

/** buffer */
typedef struct iobuf
{
	unsigned int data_sz; /**< used data Size */
	unsigned int total;	  /**< allocated size */
	char *data;			  /**< data buffer */
#ifdef DEBUG
	const char *name;
	char type;
#endif
} dynbuf_t;

#ifdef DEBUG
#define valid_iobuf(x) \
	((x) && (((x)->data_sz <= (x)->total) && ((x)->data || !((x)->total))) && (x)->name && (((x)->type == 'r') || (x)->type == 'w'))
void dynbuf_dump(dynbuf_t *);
void dynbuf_init(dynbuf_t *, char, const char *);
#else
#define valid_iobuf(x) \
	((x) && (((x)->data_sz <= (x)->total) && ((x)->data || !((x)->total))))
void dynbuf_init(dynbuf_t *);
#endif


#ifdef DEBUG
#define BUF_DBG(x)                                          \
	do                                                      \
	{                                                       \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x;                                           \
		printf("\n");                                       \
		fflush(stdout);                                     \
	} while (0)
#else
#define BUF_DBG(x)
#endif

dynbuf_t *dynbuf_new(void);
void dynbuf_free(dynbuf_t *buf);

#define assert_iobuf(x) assert(valid_iobuf(x))

void dynbuf_kill(dynbuf_t *);


#if defined(_WIN32) && !defined(__GNUC__)
#define inline __inline
#endif

static inline unsigned int dynbuf_len(dynbuf_t *buf)
{
	return buf->data_sz;
}

static inline void *dynbuf_dataptr(dynbuf_t *buf)
{
	return buf->data_sz ? buf->data : 0;
}

static inline void *dynbuf_allocptr(dynbuf_t *buf)
{
	return ((char *)buf->data) + buf->data_sz;
}

void dynbuf_consume(dynbuf_t *, unsigned int);

void *dynbuf_reserve(dynbuf_t *, unsigned int, unsigned int *);
void dynbuf_update_size(dynbuf_t *, unsigned int);
void *dynbuf_append(dynbuf_t *, const void *, unsigned int);
void dynbuf_clear(dynbuf_t *buf);
//void dynbuf_xfer(dynbuf_t *, dynbuf_t *);

#endif
