#include <string.h>
#include <sys/stat.h>
#include "janet.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_465(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a Janet object from the data
    Janet janet_data = janet_wrap_string(janet_string(data, size));

    // Create a JanetTable for the environment
    JanetTable *env = janet_table(0);

    // Create a JanetArray for the bytecode
    JanetArray *bytecode = janet_array(0);

    // Call the function-under-test
    JanetCompileResult result = janet_compile_lint(janet_data, env, data, bytecode);

    // Clean up
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

    LLVMFuzzerTestOneInput_465(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
