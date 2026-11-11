#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include "janet.h"

// Initialize Janet VM
void initialize_janet_vm() {
    janet_init();
}

// Fuzzing harness for janet_thunk_delay
int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    initialize_janet_vm();

    // Ensure the data size is sufficient to create a Janet string
    if (size == 0) {
        return 0;
    }

    // Create a Janet string from the input data
    Janet janet_input = janet_wrap_string(janet_string(data, size));

    // Call the function-under-test
    JanetFunction *result = janet_thunk_delay(janet_input);

    // Clean up Janet VM
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

    LLVMFuzzerTestOneInput_194(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
