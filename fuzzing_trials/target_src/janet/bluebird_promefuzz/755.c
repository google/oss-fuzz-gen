#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static JanetTable *create_dummy_table() {
    JanetTable *table = janet_table(10);
    return table;
}

static Janet create_dummy_key(const uint8_t *Data, size_t Size) {
    Janet key;
    if (Size > 0) {
        key = janet_wrap_string(janet_string(Data, Size));
    } else {
        key = janet_wrap_nil();
    }
    return key;
}

int LLVMFuzzerTestOneInput_755(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    janet_init();

    JanetTable *table = create_dummy_table();
    Janet key = create_dummy_key(Data, Size);
    Janet value = janet_wrap_number((double)Size);

    // Fuzz janet_table_put
    janet_table_put(table, key, value);

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet ret_ex = janet_table_get_ex(table, key, &which);

    // Fuzz janet_table_get
    Janet ret_get = janet_table_get(table, key);

    // Fuzz janet_wrap_table
    Janet wrapped_table = janet_wrap_table(table);

    // Fuzz janet_unwrap_table
    JanetTable *unwrapped_table = janet_unwrap_table(wrapped_table);

    // Fuzz janet_table_rawget
    if (unwrapped_table) {
        Janet ret_rawget = janet_table_rawget(unwrapped_table, key);
    }

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

    LLVMFuzzerTestOneInput_755(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
