#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_370(const uint8_t *data, size_t size) {
    JanetKeyword keyword;
    Janet result;

    // Ensure that the size is non-zero to avoid accessing out of bounds
    if (size == 0) {
        return 0;
    }

    // Initialize the Janet runtime
    janet_init();

    // Create a JanetKeyword from the input data
    keyword = janet_keyword(data, (int32_t)size);

    // Call the function-under-test
    result = janet_wrap_keyword(keyword);

    // Clean up the Janet runtime
    janet_deinit();

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

    LLVMFuzzerTestOneInput_370(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
