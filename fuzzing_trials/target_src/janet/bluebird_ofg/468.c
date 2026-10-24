#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for malloc and free
#include <string.h>  // Include for memcpy
#include "janet.h"

int LLVMFuzzerTestOneInput_468(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Ensure the data is null-terminated for use as a string
    char *cstr = (char *)malloc(size + 1);
    if (cstr == NULL) {
        janet_deinit();
        return 0;
    }
    memcpy(cstr, data, size);
    cstr[size] = '\0';

    // Create a dummy JanetRegExt array
    JanetRegExt reg_ext[] = {
        {NULL, NULL, NULL, NULL}
    };

    // Call the function-under-test
    janet_cfuns_ext(table, cstr, reg_ext);

    // Clean up
    free(cstr);
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

    LLVMFuzzerTestOneInput_468(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
