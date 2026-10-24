#include <cstddef>
#include <cstdint>
#include <magic.h>
#include <cstring>  // For memcpy
#include <cstdio>   // For printf

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;  // If magic_open fails, return immediately
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;  // If magic_load fails, return immediately
    }

    // Ensure the input data is not null and has a reasonable size
    if (data == NULL || size == 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test directly with the input data
    const char *result = magic_buffer(magic, data, size);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // Calculate a simple checksum of the result to ensure it's used
        size_t checksum = 0;
        for (const char *p = result; *p != '\0'; ++p) {
            checksum += static_cast<unsigned char>(*p);
        }
        // Print the checksum to ensure it's used
        printf("Checksum: %zu\n", checksum);

        // Additional processing to ensure the result affects program behavior
        if (checksum % 2 == 0) {
            printf("Even checksum\n");
        } else {
            printf("Odd checksum\n");
        }
    } else {
        // Handle the case where result is NULL
        printf("No result from magic_buffer\n");
    }

    // Clean up
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
