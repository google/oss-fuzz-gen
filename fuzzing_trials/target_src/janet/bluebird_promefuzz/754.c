#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static JanetTable *create_dummy_table() {
    JanetTable *table = (JanetTable *)malloc(sizeof(JanetTable));
    if (!table) return NULL;
    table->gc.flags = 0;
    table->gc.data.next = NULL;
    table->count = 0;
    table->capacity = 1; // Ensure capacity is non-zero
    table->deleted = 0;
    table->data = (JanetKV *)calloc(1, sizeof(JanetKV)); // Allocate memory for data
    if (!table->data) {
        free(table);
        return NULL;
    }
    table->proto = NULL;
    return table;
}

static Janet create_dummy_janet_key(const uint8_t *Data, size_t Size) {
    Janet key;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&key.u64, Data, sizeof(uint64_t));
    } else {
        key.u64 = 0;
    }
    return key;
}

int LLVMFuzzerTestOneInput_754(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    JanetTable *table = create_dummy_table();
    if (!table) return 0;

    Janet key = create_dummy_janet_key(Data, Size);

    // Ensure the key is a valid Janet value, such as a string or symbol
    key = janet_wrap_table(table); // Wrap the table itself as a key for simplicity

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet result_ex = janet_table_get_ex(table, key, &which);

    // Fuzz janet_table_get
    Janet result_get = janet_table_get(table, key);

    // Fuzz janet_table_remove
    Janet result_remove = janet_table_remove(table, key);

    // Fuzz janet_table_rawget
    Janet result_rawget = janet_table_rawget(table, key);

    // Fuzz janet_wrap_table
    Janet wrapped_table = janet_wrap_table(table);

    // Fuzz janet_unwrap_table
    JanetTable *unwrapped_table = janet_unwrap_table(wrapped_table);

    // Cleanup
    free(table->data);
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

    LLVMFuzzerTestOneInput_754(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
