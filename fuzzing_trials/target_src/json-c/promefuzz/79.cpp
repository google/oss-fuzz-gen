// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// lh_table_head at linkhash.h:349:36 in linkhash.h
// lh_entry_next at linkhash.h:427:36 in linkhash.h
// lh_entry_prev at linkhash.h:437:36 in linkhash.h
// lh_entry_set_val at linkhash.h:417:24 in linkhash.h
// lh_entry_k at linkhash.h:387:25 in linkhash.h
// lh_entry_v at linkhash.h:408:25 in linkhash.h
#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "linkhash.h"

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(lh_table) + sizeof(lh_entry)) {
        return 0;
    }

    // Initialize a dummy lh_table and entries
    lh_table table;
    lh_entry entry1, entry2;

    // Set up entries
    entry1.next = &entry2;
    entry1.prev = NULL;
    entry1.k = (void *)Data;
    entry1.v = (void *)(Data + 8);

    entry2.next = NULL;
    entry2.prev = &entry1;
    entry2.k = (void *)(Data + 16);
    entry2.v = (void *)(Data + 24);

    table.size = 2;
    table.head = &entry1;

    // Test lh_table_head
    lh_entry *head = lh_table_head(&table);
    if (head) {
        // Test lh_entry_next
        lh_entry *next = lh_entry_next(head);
        if (next) {
            // Test lh_entry_prev
            lh_entry *prev = lh_entry_prev(next);
            if (prev) {
                // Test lh_entry_set_val
                lh_entry_set_val(next, (void *)(Data + 32));

                // Test lh_entry_k
                void *key = lh_entry_k(next);

                // Test lh_entry_v
                void *value = lh_entry_v(next);
            }
        }
    }

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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    