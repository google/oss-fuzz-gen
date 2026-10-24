#include <stdint.h>
#include <janet.h>

// Initialize the Janet environment
__attribute__((constructor))
void init_janet_env() {
    janet_init();
}

// Fuzzing function
int LLVMFuzzerTestOneInput_322(const uint8_t *data, size_t size) {
    // Ensure the size is appropriate for creating a Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet object from the input data
    Janet janet_obj;
    memcpy(&janet_obj, data, sizeof(Janet));

    // Call the function-under-test
    JanetTable *table = janet_unwrap_table(janet_obj);

    // Use the table in some way if needed, for now, we just check if it's non-null
    if (table != NULL) {
        // Do something with the table if necessary
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

    LLVMFuzzerTestOneInput_322(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
