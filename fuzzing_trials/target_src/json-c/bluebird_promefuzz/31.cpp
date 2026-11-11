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
extern "C" {
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/json-c/linkhash.h"
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Ensure the input is null-terminated
    std::vector<uint8_t> input(Data, Data + Size);
    input.push_back('\0');

    // Create a dummy JSON object
    json_object *jobj = json_tokener_parse((const char *)input.data());
    if (!jobj) {
        return 0;
    }

    // Retrieve the linked hash table from the JSON object
    lh_table *table = json_object_get_object(jobj);
    if (!table) {
        json_object_put(jobj);
        return 0;
    }

    // Test lh_table_head function
    lh_entry *entry = lh_table_head(table);
    if (entry) {
        // Test lh_entry_prev function
        lh_entry *prev_entry = lh_entry_prev(entry);

        // Test lh_entry_next function
        lh_entry *next_entry = lh_entry_next(entry);

        // Test lh_entry_k function
        void *key = lh_entry_k(entry);

        // Test lh_entry_v function
        void *value = lh_entry_v(entry);

        // Test lh_table_lookup_entry_w_hash function
        if (key) {
            unsigned long hash = table->hash_fn(key);
            lh_entry *lookup_entry = lh_table_lookup_entry_w_hash(table, key, hash);
        
            // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lh_table_lookup_entry_w_hash to lh_table_delete_entry
            // Ensure dataflow is valid (i.e., non-null)
            if (!jobj) {
            	return 0;
            }
            struct lh_table* ret_json_object_get_object_mpuaj = json_object_get_object(jobj);
            if (ret_json_object_get_object_mpuaj == NULL){
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!ret_json_object_get_object_mpuaj) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!lookup_entry) {
            	return 0;
            }
            int ret_lh_table_delete_entry_midtj = lh_table_delete_entry(ret_json_object_get_object_mpuaj, lookup_entry);
            if (ret_lh_table_delete_entry_midtj < 0){
            	return 0;
            }
            // End mutation: Producer.APPEND_MUTATOR
            
}
    }

    // Clean up
    json_object_put(jobj);
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
