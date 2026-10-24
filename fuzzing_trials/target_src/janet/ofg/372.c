#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_372(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a Janet environment
    JanetTable *env = janet_table(0);

    // Create a Janet object (e.g., a string) from the input data
    Janet source = janet_stringv(data, size);

    // Call the function-under-test
    JanetCompileResult result = janet_compile(source, env, NULL);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_372(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
