#include <stdint.h>
#include <string.h> // Include for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    Janet janet_value;
    JanetKeyword keyword_result;

    if (size < sizeof(Janet)) {
        return 0;
    }

    // Copy the input data into a Janet value
    memcpy(&janet_value, data, sizeof(Janet));

    // Call the function-under-test
    keyword_result = janet_unwrap_keyword(janet_value);

    // Use the result in some way to prevent optimizations from removing the call
    if (keyword_result != NULL) {
        // Do something with keyword_result, e.g., print or log
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

    LLVMFuzzerTestOneInput_157(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
