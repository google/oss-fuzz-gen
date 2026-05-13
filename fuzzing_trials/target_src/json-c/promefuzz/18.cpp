// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// lh_table_new at linkhash.c:499:18 in linkhash.h
// lh_table_head at linkhash.h:349:36 in linkhash.h
// lh_table_length at linkhash.c:715:5 in linkhash.h
// lh_table_resize at linkhash.c:537:5 in linkhash.h
// lh_kchar_table_new at linkhash.c:527:18 in linkhash.h
// lh_table_length at linkhash.c:715:5 in linkhash.h
// lh_table_head at linkhash.h:349:36 in linkhash.h
// lh_table_resize at linkhash.c:537:5 in linkhash.h
// lh_table_delete_entry at linkhash.c:666:5 in linkhash.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "linkhash.h"

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Use the first part of the data as an integer for sizes and other parameters
    int param = *(reinterpret_cast<const int*>(Data));
    Data += sizeof(int);
    Size -= sizeof(int);

    // Test lh_table_new
    lh_table *table = lh_table_new(param, nullptr, nullptr, nullptr);
    if (table) {
        // Test lh_table_head
        lh_entry *head = lh_table_head(table);

        // Test lh_table_length
        int length = lh_table_length(table);

        // Test lh_table_resize
        if (Size >= sizeof(int)) {
            int new_size = *(reinterpret_cast<const int*>(Data));
            Data += sizeof(int);
            Size -= sizeof(int);
            lh_table_resize(table, new_size);
        }

        // Test lh_kchar_table_new
        lh_table *kchar_table = lh_kchar_table_new(param, nullptr);
        if (kchar_table) {
            lh_table_length(kchar_table);
            lh_table_head(kchar_table);
            lh_table_resize(kchar_table, param);
            free(kchar_table);
        }

        // Prepare dummy entry for lh_table_delete_entry
        lh_entry dummy_entry;
        memset(&dummy_entry, 0, sizeof(lh_entry));
        lh_table_delete_entry(table, &dummy_entry);

        // Clean up
        free(table);
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    