#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <magic.h>

extern "C" {
    // Include the function-under-test signature
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure size is at least the size of an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == nullptr) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, nullptr) != 0) {
        magic_close(ms);
        return 0;
    }

    // Extract an int from the input data
    int descriptor;
    memcpy(&descriptor, data, sizeof(int));

    // Call the function-under-test
    const char *result = magic_descriptor(ms, descriptor);

    // Print the result for debugging purposes
    if (result != nullptr) {
        printf("Magic descriptor result: %s\n", result);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
