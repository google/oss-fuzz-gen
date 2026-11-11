#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Check if the input size is zero, return immediately if true
    if (size == 0) {
        return 0;
    }

    // Initialize the adler value, it must not be NULL
    uLong adler = 1;  // Typically, the adler32 checksum starts with 1

    // Process the input data in chunks to ensure better coverage
    size_t chunk_size = 1024;  // Define a reasonable chunk size
    uLong final_result = adler;  // Accumulate results

    for (size_t offset = 0; offset < size; offset += chunk_size) {
        // Calculate the size of the current chunk
        size_t current_chunk_size = (offset + chunk_size > size) ? (size - offset) : chunk_size;

        // Always call the function-under-test with the provided data chunk
        uLong result = adler32_z(adler, (const Bytef *)(data + offset), (z_size_t)current_chunk_size);

        // Use the result in some way to avoid any compiler optimizations that
        // might skip the function call. Here, we accumulate it.
        final_result ^= result;

        // Perform a dummy operation to ensure the branch is covered
        if (result == 0) {
            final_result ^= 0xFFFFFFFF;  // Flip bits as a dummy operation
        }
    }

    // Return value is based on the accumulated result
    return (int)(final_result % 256);  // Modulo operation to ensure the return value is within a small range
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
