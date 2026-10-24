// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// lh_table_new at linkhash.c:499:18 in linkhash.h
// lh_table_free at linkhash.c:568:6 in linkhash.h
// lh_table_insert at linkhash.c:623:5 in linkhash.h
// lh_table_lookup_entry at linkhash.c:647:18 in linkhash.h
// lh_entry_k_is_constant at linkhash.h:397:23 in linkhash.h
// lh_table_delete_entry at linkhash.c:666:5 in linkhash.h
// lh_table_insert_w_hash at linkhash.c:580:5 in linkhash.h
// lh_table_free at linkhash.c:568:6 in linkhash.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "linkhash.h"

// Dummy hash function as lh_char_hash is not defined in the provided context
static unsigned long dummy_hash(const void *key) {
    return reinterpret_cast<uintptr_t>(key) % 1024;
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int initial_size = *(reinterpret_cast<const int*>(Data));
    Data += sizeof(int);
    Size -= sizeof(int);

    struct lh_table *table = lh_table_new(initial_size, nullptr, nullptr, nullptr);
    if (!table) return 0;

    if (Size < sizeof(void*) * 2) {
        lh_table_free(table);
        return 0;
    }

    const void *key = reinterpret_cast<const void*>(Data);
    const void *value = reinterpret_cast<const void*>(Data + sizeof(void*));

    lh_table_insert(table, key, value);

    struct lh_entry *entry = lh_table_lookup_entry(table, key);
    if (entry) {
        lh_entry_k_is_constant(entry);
        lh_table_delete_entry(table, entry);
    }

    lh_table_insert_w_hash(table, key, value, dummy_hash(key), 0);

    lh_table_free(table);
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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    