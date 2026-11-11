#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "plist/plist.h"

extern "C" {
    // Include the necessary headers for the function-under-test
    #include "plist/plist.h"
}

// Function-under-test
extern "C" int plist_key_val_compare_with_size(plist_t node, const char *key, size_t size);

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract a key and a value
    if (size < 2) {
        return 0;
    }

    // Initialize a plist node
    plist_t node = plist_new_dict();

    // Create a key from the input data
    size_t key_size = size > 255 ? 255 : size - 1; // Limit key size to 255, leaving space for a value
    char *key = (char *)malloc(key_size + 1);
    if (!key) {
        plist_free(node);
        return 0;
    }
    memcpy(key, data, key_size);
    key[key_size] = '\0'; // Null-terminate the key

    // Extract a value from the input data
    size_t value_size = size - key_size;
    char *value = (char *)malloc(value_size + 1);
    if (!value) {
        free(key);
        plist_free(node);
        return 0;
    }
    memcpy(value, data + key_size, value_size);
    value[value_size] = '\0'; // Null-terminate the value

    plist_dict_set_item(node, key, plist_new_string(value));

    // Call the function-under-test
    plist_key_val_compare_with_size(node, key, key_size);

    // Clean up
    free(key);
    free(value);
    plist_free(node);

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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
