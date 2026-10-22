#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure that the input data is non-empty
    if (data == NULL || size == 0) {
        return 0;
    }

    // Open a magic set with more flags to increase the coverage
    struct magic_set *magic = magic_open(MAGIC_NONE | MAGIC_MIME_TYPE | MAGIC_MIME_ENCODING);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Check the result and print only if it's not NULL
    if (result != NULL) {
        printf("Magic Buffer Result: %s\n", result);
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
