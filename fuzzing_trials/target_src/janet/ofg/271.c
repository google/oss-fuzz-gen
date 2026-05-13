#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_271(const uint8_t *data, size_t size) {
    JanetTable *table;

    /* Initialize the Janet environment */
    janet_init();

    /* Create a new Janet table */
    table = janet_table(10);

    /* Ensure the table is not NULL */
    if (table == NULL) {
        janet_deinit();
        return 0;
    }

    /* Populate the table with some data from the input */
    for (size_t i = 0; i < size; i++) {
        Janet key = janet_wrap_integer(i);
        Janet value = janet_wrap_integer(data[i]);
        janet_table_put(table, key, value);
    }

    /* Deinitialize the Janet environment */
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

    LLVMFuzzerTestOneInput_271(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
