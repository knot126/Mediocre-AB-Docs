/**
 * Program to find the Smash Hit Checksum of an APK.
 * 
 * This basically does a simple hash on the compressed contents of all *.so and
 * *classes.dex files in the APK.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

void print_usage(const char *binary_name) {
	printf("Usage: %s [path to apk file]\n", binary_name);
}

bool str_ends_with(const char * restrict string, const char * const restrict end) {
	/**
	 * Return true if `end` is a suffix of `string`.
	 */
	
	size_t string_size = strlen(string), end_size = strlen(end);
	
	if (end_size > string_size) {
		return false;
	}
	
	return !strcmp(&string[string_size - end_size], end);
}

uint16_t file_read_uint16(FILE *file) {
	uint16_t temp = 0;
	fread(&temp, sizeof temp, 1, file);
	return temp;
}

uint32_t file_read_uint32(FILE *file) {
	uint32_t temp = 0;
	fread(&temp, sizeof temp, 1, file);
	return temp;
}

uint8_t *file_read_block(FILE *file, size_t size) {
	/**
	 * Read in a block of data. Also puts a null byte at the end, but bin data
	 * is still okay to use for this.
	 */
	
	uint8_t *data = malloc(size + 1);
	
	if (!data) {
		return NULL;
	}
	
	if (fread(data, 1, size, file) != size) {
		free(data);
		return NULL;
	}
	
	data[size] = '\0';
	
	return data;
}

void file_skip(FILE *file, size_t size) {
	fseek(file, size, SEEK_CUR);
}

const uint8_t *gKey = "c+r3k7:1";

void checksum_content(uint8_t * restrict checksum, const size_t size, const uint8_t * restrict data) {
	for (size_t i = 0; i < size; i++) {
		checksum[i % 256] += gKey[i % 8] ^ data[i];
	}
}

void nopFunction(char *_, ...) {}

#if DBG_PRINTF
#define DPRINTF printf
#else
#define DPRINTF nopFunction
#endif

int main(int argc, const char *argv[]) {
	// Validate the args
	if (argc != 2) {
		print_usage(argv[0]);
		printf("\nError: Cannot take the checksum without an APK.\n");
		return 1;
	}
	
	// Open APK
	FILE *file = fopen(argv[1], "rb");
	
	// Compute the checksum
	uint8_t checksum[256] = { 0 };
	
	// For each file, load it and add it to the checksum
	while (true) {
		// Check if the next thing is a file, break if not
		uint32_t magic = file_read_uint32(file);
		
		if (magic != 0x04034b50) {
			DPRINTF("done at 0x%x : 0x%x\n", ftell(file) - 4, magic);
			break;
		}
		
		DPRINTF("Have a good file header, try to read a file\n");
		
		// Read flags and version crap
		file_read_uint16(file); // version
		uint16_t flags = file_read_uint16(file);
		
		// Skip to compressed size
		file_skip(file, 10);
		
		// Read data size
		uint32_t data_size = file_read_uint32(file);
		file_read_uint32(file); // Uncompressed size (don't care)
		uint32_t name_size = file_read_uint16(file);
		uint32_t extra_size = file_read_uint16(file);
		
		// computeChecksum does this ...
		if (name_size > 511) {
			name_size = 511;
		}
		
		DPRINTF("sizes for : data = 0x%x  name = 0x%x  extra = 0x%x\n", data_size, name_size, extra_size);
		
		// Read filename
		char *name = (char *) file_read_block(file, name_size);
		
		if (!name) {
			DPRINTF("Failed to read filename from zip structure.\n");
			return 1;
		}
		
		DPRINTF("filename: %s\n", name);
		
		// Skip extra data
		file_skip(file, extra_size);
		
		// If this file is relevant to the checksum, add it.
		if (str_ends_with(name, ".so") || str_ends_with(name, "classes.dex")) {
			uint8_t *data = file_read_block(file, data_size);
			
			if (!data) {
				printf("Failed to read block of file data from zip structure.\n");
				return 1;
			}
			
			checksum_content(checksum, data_size, data);
			
			free(data);
		}
		// Skip this file otherwise
		else {
			file_skip(file, data_size);
		}
		
		// Skip the extra data structure
		if (flags & (1 << 3)) {
			DPRINTF("skip extradata!!\n");
			file_skip(file, 16);
		}
		
		free(name);
	}
	
	// Finally, print out the checksum
	for (size_t i = 0; i < 256; i++) {
		uint32_t a = checksum[i];
		printf("%02x ", a);
		
		// Break lines every 16 bytes
		if (i % 16 == 15) {
			printf("\n");
		}
	}
	
	printf("\n");
	
	// Exit
	return 0;
}
