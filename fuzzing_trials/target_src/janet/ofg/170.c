#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Function-under-test declaration
Janet janet_cfun_stream_close(int32_t argc, Janet *argv);

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Ensure there is enough data to define argc and at least one Janet argument
    if (size < sizeof(int32_t) + sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Set argc from the input data
    int32_t argc = (int32_t)(data[0] % 10) + 1; // Limit argc to a reasonable number

    // Allocate memory for Janet arguments
    Janet *argv = (Janet *)malloc(argc * sizeof(Janet));
    if (!argv) {
        janet_deinit();
        return 0;
    }

    // Initialize Janet arguments from the input data
    for (int32_t i = 0; i < argc; i++) {
        argv[i] = janet_wrap_integer((int32_t)data[i % size]);
    }

    // Call the function-under-test
    janet_cfun_stream_close(argc, argv);

    // Clean up
    free(argv);
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

    LLVMFuzzerTestOneInput_170(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
