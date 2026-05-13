// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_dictionary_get at janet.c:34021:7 in janet.h
// janet_next at value.c:126:7 in janet.h
// janet_table_get at janet.c:33179:7 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_get at value.c:514:7 in janet.h
// janet_nextmethod at janet.c:4494:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static Janet random_janet() {
    Janet j;
    // Initialize with a valid, non-nil value
    j.u64 = rand(); // Random number, assuming non-zero for simplicity
    return j;
}

static JanetKV *random_janetkv_array(int32_t capacity) {
    JanetKV *array = (JanetKV *)malloc(sizeof(JanetKV) * capacity);
    for (int32_t i = 0; i < capacity; i++) {
        array[i].key = random_janet();
        array[i].value = random_janet();
    }
    return array;
}

static JanetTable random_janetable(int32_t capacity) {
    JanetTable table;
    table.count = capacity;
    table.capacity = capacity;
    table.deleted = 0;
    table.data = random_janetkv_array(capacity);
    table.proto = NULL;
    return table;
}

static JanetMethod *random_janetmethod_array(int32_t count) {
    JanetMethod *methods = (JanetMethod *)malloc(sizeof(JanetMethod) * count);
    for (int32_t i = 0; i < count; i++) {
        methods[i].name = "dummy_method";
        methods[i].cfun = NULL;
    }
    return methods;
}

int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) {
        return 0; // Not enough data to proceed
    }

    Janet key = *(Janet *)Data;
    int32_t capacity = *(int32_t *)(Data + sizeof(Janet));

    // Fuzz janet_dictionary_get
    JanetKV *dict_data = random_janetkv_array(capacity);
    janet_dictionary_get(dict_data, capacity, key);
    free(dict_data);

    // Fuzz janet_next
    Janet ds = random_janet();
    janet_next(ds, key);

    // Fuzz janet_table_get
    JanetTable table = random_janetable(capacity);
    janet_table_get(&table, key);

    // Fuzz janet_table_remove
    janet_table_remove(&table, key);
    free(table.data);

    // Fuzz janet_get
    janet_get(ds, key);

    // Fuzz janet_nextmethod
    int32_t method_count = capacity; // Assume the same capacity for simplicity
    JanetMethod *methods = random_janetmethod_array(method_count);
    janet_nextmethod(methods, key);
    free(methods);

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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    