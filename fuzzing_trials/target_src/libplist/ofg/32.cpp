#include <cstdint>
#include <cstring>
#include <plist/plist.h>

extern "C" {
    #include <stdlib.h>  // Include the C standard library for free
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create a valid string key
    if (size < 1) {
        return 0;
    }

    // Create a plist dictionary
    plist_t dict = plist_new_dict();

    // Create a key from the fuzzing data
    char *key = new char[size + 1];
    memcpy(key, data, size);
    key[size] = '\0';  // Null-terminate the key

    // Add a dummy uint64_t value to the dictionary with the created key
    uint64_t dummy_value = 123456789;
    plist_dict_set_item(dict, key, plist_new_uint(dummy_value));

    // Call the function-under-test
    plist_t item = plist_dict_get_item(dict, key);
    if (item && plist_get_node_type(item) == PLIST_UINT) {
        uint64_t result = 0;
        plist_get_uint_val(item, &result);

        // Check if the retrieved value matches the dummy value
        if (result != dummy_value) {
            // Handle unexpected result
        }
    }

    // Additional operations to increase code coverage
    plist_t new_item = plist_new_string(key);
    plist_dict_set_item(dict, "string_key", new_item);

    plist_t retrieved_item = plist_dict_get_item(dict, "string_key");
    if (retrieved_item && plist_get_node_type(retrieved_item) == PLIST_STRING) {
        char *retrieved_str = nullptr;
        plist_get_string_val(retrieved_item, &retrieved_str);
        if (retrieved_str) {
            // Use the retrieved string in some way
            free(retrieved_str);
        }
    }

    // Clean up
    plist_free(dict);
    delete[] key;

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
