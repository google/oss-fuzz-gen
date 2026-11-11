#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    JanetTable *table;

    if (size < sizeof(JanetTable)) {
        return 0;
    }

    // Allocate memory for a JanetTable
    table = (JanetTable *)malloc(sizeof(JanetTable));
    if (table == NULL) {
        return 0;
    }

    // Initialize the table with some data
    janet_table_init(table, 10);

    // Call the function-under-test
    janet_table_clear(table);

    // Clean up
    free(table);

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

    LLVMFuzzerTestOneInput_139(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
