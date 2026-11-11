#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function-under-test
void *janet_malloc(size_t size);

int LLVMFuzzerTestOneInput_526(const uint8_t *data, size_t size) {
    // Ensure size is not zero to avoid undefined behavior
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    void *allocated_memory = janet_malloc(size);

    // If janet_malloc returns a non-NULL pointer, free the allocated memory
    if (allocated_memory != NULL) {
        free(allocated_memory);
    }

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

    LLVMFuzzerTestOneInput_526(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
