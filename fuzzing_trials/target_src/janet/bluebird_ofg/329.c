#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_329(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10); // Arbitrary non-zero size

    // Ensure the data is null-terminated and valid for Janet symbols
    uint8_t *null_terminated_data = (uint8_t *) malloc(size + 1);
    if (null_terminated_data == NULL) {
        janet_deinit();
        return 0; // Handle allocation failure
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Ensure the input is a valid Janet symbol
    for (size_t i = 0; i < size; i++) {
        if (null_terminated_data[i] == '\0' || null_terminated_data[i] == ':' || null_terminated_data[i] == ';') {
            null_terminated_data[i] = '_'; // Replace invalid characters
        }
    }

    // Check if the input is a valid Janet symbol
    JanetSymbol symbol = janet_symbol(null_terminated_data, size);
    if (symbol == NULL) {
        free(null_terminated_data);
        janet_deinit();
        return 0; // If not a valid symbol, exit early
    }

    // Call the function-under-test
    Janet result = janet_table_get(table, janet_ckeywordv(symbol));

    // Clean up
    free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_329(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
