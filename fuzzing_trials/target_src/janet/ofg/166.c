#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Call the function-under-test
    Janet last_error = janet_ev_lasterr();

    // Check the type of the returned Janet value
    if (janet_checktype(last_error, JANET_STRING)) {
        // If it's a string, print it (for debugging purposes)
        const uint8_t *str = janet_unwrap_string(last_error);
        (void)str; // Avoid unused variable warning in non-debug mode
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

    LLVMFuzzerTestOneInput_166(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
