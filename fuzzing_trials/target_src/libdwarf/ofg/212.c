#include <stddef.h>
#include <stdint.h>

// Function-under-test declaration
unsigned int dwarf_basic_crc32(const unsigned char *buf, unsigned long len, unsigned int crc);

int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Use the input data as the buffer
    const unsigned char *buffer = data;

    // Use the size of the data as the length
    unsigned long length = (unsigned long)size;

    // Use the first byte of data as the initial CRC value
    unsigned int initial_crc = (unsigned int)data[0];

    // Call the function-under-test
    unsigned int result = dwarf_basic_crc32(buffer, length, initial_crc);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_212(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
