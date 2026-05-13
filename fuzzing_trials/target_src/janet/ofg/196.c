#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h" // Assuming this is the header where JanetTable is defined

int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an int32_t
    if (size < sizeof(int32_t)) return 0;

    // Extract an int32_t from the input data
    int32_t capacity = *(const int32_t *)data;
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    // Adjust capacity to be positive if necessary
    if (capacity <= 0) capacity = 1;

    // Initialize JanetTable structure
    JanetTable table;
    JanetTable *result = janet_table_init_raw(&table, capacity);

    // Check if the result is not NULL
    if (result == NULL) {
        // Handle the error case if needed
        return 0;
    }

    // Use the remaining data to perform operations on the table
    while (size >= sizeof(int32_t)) {
        // Extract length for key
        int32_t key_length = *(const int32_t *)data;
        data += sizeof(int32_t);
        size -= sizeof(int32_t);

        // Ensure key_length is positive and within remaining size
        if (key_length <= 0 || key_length > size) break;

        // Allocate memory for the key
        char *dynamic_key = (char *)malloc(key_length + 1);
        if (!dynamic_key) break;

        // Copy the key data
        memcpy(dynamic_key, data, key_length);
        dynamic_key[key_length] = '\0';
        data += key_length;
        size -= key_length;

        // Use remaining data for value if possible
        int32_t value_length = size > 0 ? (int32_t)(data[0] % (size + 1)) : 0;
        if (value_length > size) value_length = size;
        
        char *dynamic_value = (char *)malloc(value_length + 1);
        if (!dynamic_value) {
            free(dynamic_key);
            break;
        }

        memcpy(dynamic_value, data, value_length);
        dynamic_value[value_length] = '\0';
        data += value_length;
        size -= value_length;

        // Insert into table
        janet_table_put(result, janet_ckeywordv(dynamic_key), janet_cstringv(dynamic_value));

        // Free allocated memory
        free(dynamic_key);
        free(dynamic_value);
    }

    // Further operations can be added to verify the integrity of the table
    // For example, iterate over the table and perform some operations

    // To maximize fuzzing results, ensure we are using the table by performing some operations
    // Iterate over the table to simulate usage
    JanetKV *kv;
    for (kv = result->data; kv < result->data + result->capacity; kv++) {
        if (janet_checktype(kv->key, JANET_NIL)) continue;
        // Perform some dummy operations
        (void)janet_length(kv->key);
        (void)janet_length(kv->value);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_196(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
