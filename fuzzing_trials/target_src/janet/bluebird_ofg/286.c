#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_286(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a Janet object
    if (size < sizeof(double)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Create a Janet object from the input data
    Janet janet_obj;
    janet_obj = janet_wrap_number(*(double *)data); // Use data to initialize the number

    // Use an index within a reasonable range
    int32_t index = 0; // Example index, adjust as needed

    // Create a JanetTable to use with janet_gettable
    JanetTable *table = janet_table(10);
    janet_table_put(table, janet_ckeywordv("example"), janet_obj);

    // Call the function-under-test
    Janet value = janet_table_get(table, janet_ckeywordv("example"));

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

    LLVMFuzzerTestOneInput_286(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
