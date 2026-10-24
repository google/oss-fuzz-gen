#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Function prototype for the function-under-test
void hts_md5_hex(char *hex, const unsigned char *data);

// Define the size of the MD5 hash in hexadecimal representation
#define MD5_HEX_SIZE 33 // 32 characters for the hash and 1 for the null terminator
#define MD5_INPUT_SIZE 16 // MD5 operates on 128-bit (16-byte) blocks

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Ensure the input data is at least MD5_INPUT_SIZE bytes long
    if (size < MD5_INPUT_SIZE) {
        return 0;
    }

    // Allocate memory for the MD5 hash in hexadecimal form
    char hex[MD5_HEX_SIZE];
    memset(hex, 0, MD5_HEX_SIZE);

    // Call the function-under-test with the first MD5_INPUT_SIZE bytes of data
    hts_md5_hex(hex, data);

    // Optionally, you can add additional checks or processing of 'hex' here
    // For example, ensure that the 'hex' output is a valid hexadecimal string
    for (int i = 0; i < MD5_HEX_SIZE - 1; i++) {
        if (!((hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f'))) {
            abort(); // If the output is not valid hex, abort to catch the error
        }
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
