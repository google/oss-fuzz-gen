#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_308(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Check if the size is sufficient to create a Janet string
    if (size == 0) {
        janet_deinit();
        return 0;
    }

    // Create a Janet string from the input data
    JanetString janet_str = janet_string(data, size);

    // Wrap the Janet string in a Janet object
    Janet janet_obj = janet_wrap_string(janet_str);

    // Prepare the Janet array with at least one element
    Janet janet_array[1];
    janet_array[0] = janet_obj;

    // Create a Janet table and insert the Janet object into the table
    JanetTable *table = janet_table(0); // Create an empty table
    janet_table_put(table, janet_ckeywordv("key"), janet_obj); // Insert the Janet object into the table

    // Convert the table to a dictionary view
    const JanetKV *data_view;
    int32_t len, cap;
    janet_dictionary_view(janet_wrap_table(table), &data_view, &len, &cap);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_308(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
