#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <magic.h>
#include <cstdio>  // Include for printf

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Check if the input data is not empty
    if (data == NULL || size == 0) {
        return 0;
    }

    // Initialize magic_set
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // If magic_open fails, return immediately
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // If magic_load fails, return immediately
    }

    // Call the function-under-test
    const char *result = magic_buffer(ms, data, size);

    // Check the result and do something with it
    if (result != NULL) {
        // Print the result to ensure the function is being exercised
        printf("Magic buffer result: %s\n", result);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
