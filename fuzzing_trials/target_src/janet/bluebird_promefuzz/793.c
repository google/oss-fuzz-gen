#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static void initialize_dummy_data(JanetKV *data, int32_t capacity) {
    for (int32_t i = 0; i < capacity; i++) {
        data[i].key.u64 = i + 1; // Simple non-NIL initialization
        data[i].value.u64 = i + 100; // Arbitrary value
    }
}

static Janet create_valid_janet_key(const uint8_t *Data, size_t Size) {
    Janet key;
    if (Size >= sizeof(uint64_t)) {
        key.u64 = *((uint64_t *)Data);
    } else {
        key.u64 = 1; // Use a default valid key
    }
    // Ensure the key is a valid Janet type
    // Here we wrap the key as a number since it's a simple and valid Janet type
    return janet_wrap_number((double)key.u64);
}

int LLVMFuzzerTestOneInput_793(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    int32_t capacity = 10;
    JanetKV data[capacity];
    initialize_dummy_data(data, capacity);

    // Fuzz janet_dictionary_get
    Janet key = create_valid_janet_key(Data, Size);
    Janet result = janet_dictionary_get(data, capacity, key);

    // Fuzz janet_table_init
    JanetTable table;
    janet_table_init(&table, capacity);

    // Fuzz janet_dictionary_next
    const JanetKV *next_kv = janet_dictionary_next(data, capacity, NULL);

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet table_result = janet_table_get_ex(&table, key, &which);

    // Fuzz janet_dictionary_view
    const JanetKV *view_data = NULL;
    int32_t len = 0, cap = 0;
    int view_result = janet_dictionary_view(janet_wrap_table(&table), &view_data, &len, &cap);

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

    LLVMFuzzerTestOneInput_793(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
