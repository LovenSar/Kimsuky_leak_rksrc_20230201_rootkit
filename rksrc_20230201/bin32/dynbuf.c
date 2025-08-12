/*
 */
#include "dynbuf.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef DEBUG
#include <stdio.h>
#endif

/**
 * @brief initialize I/O buffer
 * @param[out] buf buffer to initialize
 */
#ifdef DEBUG
void dynbuf_init(dynbuf_t *buf, char type, const char *name)
#else
void dynbuf_init(dynbuf_t *buf)
#endif
{
	//assert(buf);

	buf->data = NULL;
	buf->data_sz = 0;
	buf->total = 0;
#ifdef DEBUG
	buf->name = name;
	buf->type = type;
#endif

	BUF_DBG(("[%c] %s", type, name));
}

dynbuf_t *dynbuf_new(void)
{
	dynbuf_t *buf = NULL;

	if ((buf = (dynbuf_t *)calloc(sizeof(*buf), 1)) == NULL)
		return NULL;
#ifdef DEBUG
	dynbuf_init(buf, 'alloc', name);
#else
	dynbuf_init(buf);
#endif

	return buf;
}

/**
 * destroy an I/O buffer
 * @param[in] buf buffer to destroy
 */
void dynbuf_kill(dynbuf_t *buf)
{
	//assert_iobuf(buf);
#ifdef DEBUG
	buf_dbg(("[%c] %s", buf->type, buf->name));
#endif

	if (buf->data != NULL)
	{
		free(buf->data);
		
		buf->data = NULL;
	}

	if (buf != NULL)
	{
		free(buf);
		
		buf = NULL;
	}
}

void dynbuf_free(dynbuf_t *buf)
{
	dynbuf_kill(buf);
}

/**
 * @brief consume data in an I/O buffer
 * @param[in] buf I/O buffer where data will be consumed
 * @param[in] consumed size of consumed data
 */
void dynbuf_consume(dynbuf_t *buf, unsigned int consumed)
{
	unsigned int size;

	//assert(valid_iobuf(buf) && (consumed > 0) && (consumed <= buf->data_sz));

	size = buf->data_sz - consumed;
	BUF_DBG(("[%c] %s, consumed=%u, remaining=%u", buf->type, buf->name, consumed, size));

	if (size)
		memmove(buf->data, buf->data + consumed, size);

	buf->data_sz = size;
}

/**
 * @brief reserve space in an I/O buffer
 * @param[in] buf I/O buffer where data will be written
 * @param[in] size size to reserve
 * @param[out] reserved will hold the size of allocated data
 * @return pointer where data have been allocated
 * @note if size is 0 reserved must be non-NULL
 */
void *dynbuf_reserve(dynbuf_t *buf, unsigned int size, unsigned int *reserved)
{
	unsigned int avail;
	void *bak, *data;

	//assert(valid_iobuf(buf) && (size || reserved));

	avail = buf->total - buf->data_sz;

	if (!size)
		size = IOBUF_MIN_SIZE;

	BUF_DBG(("[%c] %s, size=%u, avail=%u", buf->type, buf->name, size, avail));

	if (size > avail)
	{
		bak = buf->data;
		data = realloc(bak, buf->data_sz + size);
		if (!data)
			return NULL;

		buf->data = (char *)data;
		buf->total = buf->data_sz + size;
	}

	if (reserved)
		*reserved = size;

	return buf->data + buf->data_sz;
}

/**
 * commit data to an I/O buffer
 * @param[in] buf I/O buffer where data have been written
 * @param[in] commited size of data to commit
 * @note data must have been previously allocated with dynbuf_reserve
 */
void dynbuf_update_size(dynbuf_t *buf, unsigned int commited)
{
	//assert(valid_iobuf(buf) && (commited > 0) && (commited <= (buf->total - buf->data_sz)));
	BUF_DBG(("[%c] %s, commited=%u, total=%u, size=%u", buf->type, buf->name, commited, buf->total, buf->data_sz));

	buf->data_sz += commited;
}

/**
 * append data to an I/O buffer
 * @param[in] buf I/O buffer to hold data
 * @param[in] data content to append
 * @param[in] size size of data to append
 * @return pointer where data have been written or NULL if memory
 *         cannot be allocated
 */
void *dynbuf_append(dynbuf_t *buf, const void *data, unsigned int size)
{
	void *ptr;

	//assert(valid_iobuf(buf) && data && size);
	BUF_DBG(("[%c] %s, size=%u", buf->type, buf->name, size));

	ptr = dynbuf_reserve(buf, size, NULL);
	if (!ptr)
		return NULL;
	memcpy(ptr, data, size);

	dynbuf_update_size(buf, size);

	return ptr;
}

void dynbuf_clear(dynbuf_t *buf)
{
	unsigned int len;

	len = dynbuf_len(buf);
    if(len > 0)
    {
		dynbuf_consume(buf, len);
    }
	
}

#ifdef DEBUG
void dynbuf_dump(dynbuf_t *buf)
{
	unsigned int i, len;
	unsigned char *data;

	data = (unsigned char *)dynbuf_dataptr(buf);
	fprintf(stderr, "[%s-%c] ", buf->name, buf->type);

	for (i = 0, len = dynbuf_len(buf); i < len; ++i)
		fprintf(stderr, "%02x", data[i]);
		
	fputc('\n', stderr);
}

int main(int argc, char **argv)
{
	dynbuf_t *obuf = dynbuf_new();
	char test[] = {
		'1',
		'2',
		'3',
		'4',
		'5',
		'6',
	};
	int len = sizeof(test) / sizeof(test[0]);

	dynbuf_append(obuf, test, len);

	dynbuf_dump(obuf);

	return 0;
}

#endif
