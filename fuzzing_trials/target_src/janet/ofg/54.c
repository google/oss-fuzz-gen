#include <stdint.h>
#include <stddef.h>
#include "/src/janet/src/include/janet.h"

// Initialize the Janet environment
__attribute__((constructor))
static void init_janet_env() {
    janet_init();
}

// Fuzzing harness for janet_array_peek function
int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Create a Janet array with a fixed size for fuzzing
    JanetArray *array = janet_array(10);

    // Populate the Janet array with some data
    for (size_t i = 0; i < 10 && i < size; i++) {
        Janet value = janet_wrap_integer(data[i]);
        janet_array_push(array, value);
    }

    // Call the function-under-test
    Janet result = janet_array_peek(array);

    // No explicit clean-up is required for Janet arrays as they are garbage collected

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

    LLVMFuzzerTestOneInput_54(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
