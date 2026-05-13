#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Removed extern "C" since this is C code, not C++
int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a pointer and a uint64_t
    if (size < sizeof(void*) + sizeof(uint64_t)) {
        return 0;
    }
    
    // Extract pointer from data
    const void *ptr = (const void *)(data);

    // Extract uint64_t value from data
    uint64_t value = *(const uint64_t *)(data + sizeof(void*));

    // Call the function-under-test
    Janet result = janet_nanbox_from_cpointer(ptr, value);

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

    LLVMFuzzerTestOneInput_117(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
