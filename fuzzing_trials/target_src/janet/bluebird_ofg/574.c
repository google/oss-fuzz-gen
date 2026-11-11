#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_574(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize the Janet runtime before using any Janet functions
    janet_init();

    // Ensure that the data is null-terminated to safely create a JanetString
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        janet_deinit(); // Deinitialize Janet runtime if malloc fails
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Create a Janet string value
    Janet janet_string_value = janet_cstringv(null_terminated_data);

    // Call the function-under-test
    Janet result = janet_wrap_string(janet_unwrap_string(janet_string_value));

    // Clean up
    free(null_terminated_data);

    // Deinitialize the Janet runtime after using Janet functions
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

    LLVMFuzzerTestOneInput_574(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
