#include <stdint.h>
#include <string.h>
#include <janet.h>

// Ensure that the Janet library is properly initialized
__attribute__((constructor))
static void init_janet(void) {
    janet_init();
}

// Ensure that the Janet library is properly cleaned up
// __attribute__((destructor))
// static void cleanup_janet(void) {
//     janet_deinit();
// }

int LLVMFuzzerTestOneInput_291(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0; // Ensure there's enough data to form a Janet object
    }

    // Create a Janet object from the input data
    Janet janet_input;
    memcpy(&janet_input, data, sizeof(Janet));

    // Call the function-under-test
    JanetType type = janet_type(janet_input);

    // Use the result (type) in some way to avoid compiler optimizations
    // that might remove the call to janet_type
    if (type == JANET_NUMBER) {
        // Do something if the type is a number
    }

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

    LLVMFuzzerTestOneInput_291(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
