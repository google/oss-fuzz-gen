#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Define the fuzzer entry point
int LLVMFuzzerTestOneInput_374(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(JanetKV)) {
        return 0;
    }

    // Initialize Janet runtime
    janet_init();

    // Create a Janet array from the input data
    Janet *janet_array = (Janet *)data;

    // Use part of the input data as JanetKV
    const JanetKV *janet_kv = (const JanetKV *)(data + sizeof(Janet));

    // Define arbitrary int32_t values
    int32_t index = 0;
    int32_t def = 0;

    // Call the function-under-test
    JanetStruct result = janet_optstruct(janet_array, index, def, janet_kv);

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

    LLVMFuzzerTestOneInput_374(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
