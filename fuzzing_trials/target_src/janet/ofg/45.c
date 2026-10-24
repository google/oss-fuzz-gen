#include <stdint.h>
#include <stddef.h>
#include <janet.h> // Assuming the Janet library is available and this is the correct header

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure there is enough data to use for the function parameters
    if (size < sizeof(void*) + sizeof(uint64_t)) {
        return 0;
    }

    // Use the first part of the data as a pointer
    void *ptr = (void*)(data);

    // Use the second part of the data as a uint64_t
    uint64_t num = *(uint64_t*)(data + sizeof(void*));

    // Call the function-under-test
    Janet result = janet_nanbox_from_pointer(ptr, num);

    // Use the result in some way to prevent compiler optimizations from removing the call
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

    LLVMFuzzerTestOneInput_45(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
