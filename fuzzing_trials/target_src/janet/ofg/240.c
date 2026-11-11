#include <stddef.h>
#include <stdint.h>

// Function under test
void *janet_smalloc(size_t);

// Fuzzing harness
int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero to avoid unnecessary calls with zero size
    if (size == 0) {
        return 0;
    }

    // Use the size from the fuzzer input to call janet_smalloc
    void *result = janet_smalloc(size);

    // Normally, you would do something with the result, like free it
    // But since we don't have the context of janet_smalloc, we'll just return
    // Assuming janet_smalloc handles its own memory management

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

    LLVMFuzzerTestOneInput_240(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
