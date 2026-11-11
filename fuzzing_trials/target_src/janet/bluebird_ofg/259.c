#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_259(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    JanetTable *env = janet_table(0);
    Janet result;
    
    // Ensure the input data is null-terminated for use as a C string
    char *source = (char *)malloc(size + 1);
    if (!source) {
        janet_deinit();
        return 0;
    }
    memcpy(source, data, size);
    source[size] = '\0';

    // Use a fixed string for the filename parameter
    const char *filename = "fuzz_input";

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of janet_dostring
    janet_dostring(env, (const char *)"r", filename, &result);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Clean up
    free(source);

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_259(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
