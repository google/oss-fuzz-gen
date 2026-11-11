#include <sys/stat.h>
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
#include "/src/json-c/linkhash.h"
#include <string.h>
#include <stdlib.h>

static void free_entry(lh_entry *e) {
    // Example free function for entries
    if (e) {
        free(const_cast<void*>(e->k));
        free(const_cast<void*>(e->v));
    }
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there's enough data for key and value

    // Create a new table with pointer keys
    struct lh_table *table = lh_kptr_table_new(4, free_entry);
    if (!table) return 0;

    // Use some of the data as a key and value
    size_t key_len = Size / 2;
    size_t value_len = Size - key_len;
    char *key = (char *)malloc(key_len + 1);
    char *value = (char *)malloc(value_len + 1);

    if (!key || !value) {
        free(key);
        free(value);
        lh_table_free(table);
        return 0;
    }

    memcpy(key, Data, key_len);
    key[key_len] = '\0';
    memcpy(value, Data + key_len, value_len);
    value[value_len] = '\0';

    // Insert the key-value pair into the table
    lh_table_insert(table, key, value);

    // Lookup the key in the table
    void *found_value = NULL;
    lh_table_lookup_ex(table, key, &found_value);

    // Delete the entry if found
    if (found_value) {
        struct lh_entry *entry = lh_table_lookup_entry(table, key);
        if (entry) {
            lh_table_delete_entry(table, entry);
        }
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
