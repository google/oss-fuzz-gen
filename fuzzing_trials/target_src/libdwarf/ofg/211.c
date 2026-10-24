#include <stdint.h>
#include <stddef.h>

extern unsigned int dwarf_basic_crc32(const unsigned char *buf, unsigned long len, unsigned int crc);

int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    // Ensure that the input size is non-zero to avoid passing a NULL pointer
    if (size == 0) return 0;

    // Use the input data directly as the buffer
    const unsigned char *buffer = data;
    unsigned long length = (unsigned long)size;

    // Use a fixed initial CRC value for testing
    unsigned int initial_crc = 0xFFFFFFFF;

    // Call the function-under-test
    unsigned int result_crc = dwarf_basic_crc32(buffer, length, initial_crc);

    // Optionally, use the result_crc for further logic or checks
    // For this fuzzing harness, we simply return 0
    (void)result_crc; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_211(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
