#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_388(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create a Janet string from the input data
    Janet janet_str = janet_stringv(data, size);

    // Create a null-terminated C string from the input data
    char c_str[size + 1];
    for (size_t i = 0; i < size; i++) {
        c_str[i] = (char)data[i];
    }
    c_str[size] = '\0';

    // Call the function-under-test
    int result = janet_streq(janet_str, c_str);

    // Clean up Janet
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

    LLVMFuzzerTestOneInput_388(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
