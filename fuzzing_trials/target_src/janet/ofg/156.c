#include <stdint.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Ensure there is data to process
    if (size == 0) {
        janet_deinit();
        return 0;
    }

    // Create a Janet string from the input data
    Janet janet_input = janet_wrap_string(janet_string(data, size));

    // Call the function-under-test
    JanetKeyword result = janet_unwrap_keyword(janet_input);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != NULL) {
        // Print the keyword for debugging purposes (not necessary for fuzzing)
        janet_printf("Keyword: %s\n", result);
    }

    // Deinitialize Janet runtime
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

    LLVMFuzzerTestOneInput_156(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
