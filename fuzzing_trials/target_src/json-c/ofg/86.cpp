#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstddef>
#include <cstdlib>  // Include for std::abort
#include <cstring>  // Include for std::memcpy
#include "/src/json-c/linkhash.h"  // Include the correct header where lh_kchar_table_new is declared

// Define a dummy lh_entry_free_fn function pointer type
typedef void (lh_entry_free_fn)(struct lh_entry *);

// Define a dummy function that matches the lh_entry_free_fn signature
void dummy_free_function(struct lh_entry *entry) {
    // Dummy implementation: do nothing
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume an integer value for the first parameter
    int int_param = fuzzed_data.ConsumeIntegralInRange<int>(1, 100); // Ensure a valid range to prevent invalid table size

    // Use the dummy_free_function for the second parameter
    lh_entry_free_fn *free_fn_param = dummy_free_function;

    // Call the function-under-test
    struct lh_table *result = lh_kchar_table_new(int_param, free_fn_param);

    if (result == nullptr) {
        // Handle the case where lh_kchar_table_new returns null
        return 0;
    }

    // To increase the code coverage, we need to perform some operations on the table
    // Let's add some entries to the table if possible
    int num_entries = fuzzed_data.ConsumeIntegralInRange<int>(1, int_param);
    for (int i = 0; i < num_entries; ++i) {
        std::string key = fuzzed_data.ConsumeRandomLengthString(10);
        std::string value = fuzzed_data.ConsumeRandomLengthString(10);
        
        // Insert the key-value pair into the hash table
        lh_table_insert(result, strdup(key.c_str()), strdup(value.c_str()));
    }

    // Normally, you would do something with the result here, such as checking
    // for null or performing additional operations. For this task, we'll just
    // clean up and return 0.
    lh_table_free(result); // Free the allocated table to avoid memory leaks

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
