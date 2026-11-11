#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "janet.h"

static void initialize_janet_table(JanetTable *table) {
    table->count = 0;
    table->capacity = 8;
    table->deleted = 0;
    table->data = (JanetKV *)calloc(table->capacity, sizeof(JanetKV));
    table->proto = NULL;
}

static Janet create_random_janet_key(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) return janet_wrap_nil();
    int64_t key_value = *((int64_t *)Data);
    return janet_wrap_integer(key_value);
}

static void fuzz_janet_table_functions(JanetTable *table, const uint8_t *Data, size_t Size) {
    Janet key = create_random_janet_key(Data, Size);
    Janet value = janet_wrap_nil();

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet result_ex = janet_table_get_ex(table, key, &which);

    // Fuzz janet_table_get
    Janet result_get = janet_table_get(table, key);

    // Fuzz janet_table_rawget
    Janet result_rawget = janet_table_rawget(table, key);

    // Fuzz janet_wrap_table
    Janet wrapped_table = janet_wrap_table(table);

    // Fuzz janet_table_put
    janet_table_put(table, key, value);

    // Fuzz janet_unwrap_table
    JanetTable *unwrapped_table = janet_unwrap_table(wrapped_table);

    // Ensure no memory leaks or invalid memory accesses
    (void)result_ex;
    (void)result_get;
    (void)result_rawget;
    (void)unwrapped_table;
}

int LLVMFuzzerTestOneInput_866(const uint8_t *Data, size_t Size) {
    JanetTable table;
    initialize_janet_table(&table);

    fuzz_janet_table_functions(&table, Data, Size);

    free(table.data);
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

    LLVMFuzzerTestOneInput_866(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
