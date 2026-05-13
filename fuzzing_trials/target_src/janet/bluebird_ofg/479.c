#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function-under-test
int janet_dostring(JanetTable *env, const char *str, const char *source, Janet *out);

int LLVMFuzzerTestOneInput_479(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetTable for the environment
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of janet_table
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function janet_table with janet_table_weakkv
    JanetTable *env = janet_table_weakkv(JANET_SANDBOX_THREADS);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Ensure the input data is null-terminated for the string parameters
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Use a static source name for simplicity
    const char *source = "fuzz_source";

    // Prepare a Janet variable to capture the output
    Janet out;

    // Call the function-under-test
    janet_dostring(env, str, source, &out);

    // Clean up
    free(str);
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

    LLVMFuzzerTestOneInput_479(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
