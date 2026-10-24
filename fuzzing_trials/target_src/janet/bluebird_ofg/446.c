#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

// Initialize Janet runtime
void initialize_janet_446() {
    janet_init();
    // Use a valid Janet value instead of NULL
    Janet nil_value = janet_wrap_nil();
    janet_gcroot(nil_value);
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput_446(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Initialize Janet runtime
    initialize_janet_446();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Populate the table with some data from the fuzz input
    for (size_t i = 0; i < size; i++) {
        Janet key = janet_wrap_integer(i);
        Janet value = janet_wrap_integer(data[i]);
        janet_table_put(table, key, value);
    }

    // Call the function-under-test
    JanetStruct result = janet_table_to_struct(table);

    // Clean up
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

    LLVMFuzzerTestOneInput_446(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
