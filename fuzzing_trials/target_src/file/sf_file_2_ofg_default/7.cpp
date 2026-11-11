#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <magic.h>

extern "C" {
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // If magic_open fails, exit early
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // If magic_load fails, exit early
    }

    // Ensure the input data is not null and has a valid size
    if (data == NULL || size == 0) {
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test with the provided data
    const char *result = magic_buffer(ms, data, size);

    // Check the result (optional, for debugging purposes)
    if (result != NULL) {
        // Log the result to ensure the function is being exercised
        // This helps in verifying that the function processes the input
        fprintf(stderr, "Result: %s\n", result);
    } else {
        // Log an error if magic_buffer returns NULL
        fprintf(stderr, "Error: magic_buffer returned NULL\n");
    }

    // Clean up
    magic_close(ms);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
