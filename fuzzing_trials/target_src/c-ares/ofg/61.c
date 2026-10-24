#include <stddef.h>
#include <stdlib.h>
#include "ares.h"

// Custom memory allocation functions
void *custom_malloc_61(size_t size) {
    return malloc(size);
}

void custom_free_61(void *ptr) {
    free(ptr);
}

void *custom_realloc_61(void *ptr, size_t size) {
    return realloc(ptr, size);
}

// Entrypoint for Clang's libfuzzer
int LLVMFuzzerTestOneInput_61(const unsigned char *data, size_t size) {
    // Use the first byte of data as flags if size is greater than 0
    int flags = (size > 0) ? data[0] : 0;

    // Call the function-under-test
    ares_library_init_mem(flags, custom_malloc_61, custom_free_61, custom_realloc_61);

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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
