#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Call the function-under-test
    Janet result = janet_wrap_true();

    // Use the result in some way to ensure it is not optimized away
    if (janet_truthy(result)) {
        // Do something with the result, like printing or further processing
        // In this case, we simply check if it is truthy
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

    LLVMFuzzerTestOneInput_123(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
