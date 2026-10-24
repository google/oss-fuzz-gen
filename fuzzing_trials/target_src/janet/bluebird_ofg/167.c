#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Define a simple JanetReg array for testing
static const JanetReg sample_cfuns[] = {
    {"example", NULL, NULL},
    {NULL, NULL, NULL} // Null terminate the array
};

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Initialize the Janet VM
    janet_init();

    // Create a new JanetTable
    JanetTable *env = janet_table(10);

    // Ensure the data is null-terminated for use as a string
    char *prefix = (char *)janet_string(data, size);

    // Call the function-under-test
    janet_cfuns_prefix(env, prefix, sample_cfuns);

    // Clean up the Janet VM
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

    LLVMFuzzerTestOneInput_167(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
