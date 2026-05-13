#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_358(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a Janet array to use as the first argument
    JanetArray *array = janet_array(1);
    Janet first_arg = janet_wrap_array(array);

    // Create a Janet string from the input data to use as the second argument
    Janet second_arg;
    if (size > 0) {
        second_arg = janet_wrap_string(janet_string(data, size));
    } else {
        // Use a default non-empty string if size is 0
        const uint8_t default_str[] = "default";
        second_arg = janet_wrap_string(janet_string(default_str, sizeof(default_str) - 1));
    }

    // Call the function-under-test
    Janet result = janet_get(first_arg, second_arg);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_358(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
