#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize magic set
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Failed to open magic, exit early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Failed to load magic database, exit early
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, data, size);

    // Use the result in some way to avoid compiler optimizations
    if (result != NULL) {
        volatile char dummy = result[0];
        (void)dummy;
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
