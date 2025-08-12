
// gcc encode.c -lutil  -static -static-libgcc -s -o encode

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


inline void block_xor(char buf[], size_t buf_len, uint32_t _key, size_t key_len)
{
	size_t idx;
	char *key = (char *)&_key;

	for (idx = 0; idx < buf_len; idx++)
	{
		buf[idx] ^= key[idx % key_len];
	}
}


static long get_file_size(FILE *file)
{
	long size;
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	rewind(file);
	return size;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: encode <file> <pass:hex(uint32)>\n");
		exit(-1);
	}

	FILE *file = fopen(argv[1], "rb");
	if (!file) {
		fprintf(stderr, "Can't open %s \n", argv[1]);
		exit(-1);
	}

	long size = get_file_size(file);
	unsigned char *data = malloc(size);
	if (!data) {
		fprintf(stderr, "Can't allocate \n");
		exit(-1);
	}

	if (fread(data, size, 1, file) != 1) {
		fprintf(stderr, "Can't read data \n");
		exit(-1);
	}

	fclose(file);

	uint32_t key = strtol(argv[2], NULL, 16);

	block_xor(data, size, key, sizeof(uint32_t));

	printf("#define FILE_XOR_KEY 0x%08x\n", key);
	
	int i;
	for (i = 0; i < size; i++) {
		printf("0x%02x,", data[i]);
	}

	return 0;
}
