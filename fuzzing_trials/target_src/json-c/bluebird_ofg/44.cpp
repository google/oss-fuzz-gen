#include <sys/stat.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/linkhash.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string> // Include string library for std::string

// Define a simple equality function for comparing keys
static int simple_equality_function(const void *k1, const void *k2) {
    return strcmp((const char *)k1, (const char *)k2) == 0;
}

// Define a simple hash function for keys
static unsigned long simple_hash_function(const void *key) {
    const char *str = (const char *)key;
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a dummy lh_table with a valid hash function and equality function
    struct lh_table *table = lh_table_new(10, NULL, &simple_hash_function, &simple_equality_function);

    // Check if table creation was successful
    if (!table) {
        return 0;
    }

    // Consume a portion of the input data to create a key
    size_t key_size = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 100);
    std::string key_data = fuzzed_data.ConsumeRandomLengthString(key_size);

    // Validate the size of the key_data
    if (key_data.size() != key_size) {
        lh_table_free(table);
        return 0;
    }

    const void *key = key_data.data();

    // Prepare a value pointer
    void *value = nullptr;

    // Insert a dummy entry to ensure the table is not empty
    std::string dummy_key = "dummy";
    std::string dummy_value = "value";
    lh_table_insert(table, dummy_key.c_str(), (void *)dummy_value.c_str());

    // Call the function-under-test
    lh_table_lookup_ex(table, key, &value);

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
