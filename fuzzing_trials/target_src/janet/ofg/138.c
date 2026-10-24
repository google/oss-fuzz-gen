#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

// Initialize the Janet environment before using any Janet functions
__attribute__((constructor))
static void init_janet_env() {
    janet_init();
}

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a Janet object and access an index
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Initialize a Janet object from the input data
    Janet janet_obj;
    memcpy(&janet_obj, data, sizeof(Janet));

    // Extract an int32_t index from the input data
    int32_t index;
    memcpy(&index, data + sizeof(Janet), sizeof(int32_t));

    // Ensure the Janet object is valid before calling janet_getfunction
    if (!janet_checktype(janet_obj, JANET_FUNCTION)) {
        return 0;
    }

    // Call the function-under-test
    JanetFunction *result = janet_getfunction(&janet_obj, index);

    // Optionally, perform some operations with the result (if needed)
    // For now, we just ensure the function is called

    return 0;
}

// Clean up the Janet environment after fuzzing is done
// __attribute__((destructor))
// static void cleanup_janet_env() {
//     janet_deinit();
// }
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

    LLVMFuzzerTestOneInput_138(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
