extern "C" {
#include "/src/libplist/libcnary/include/node.h"
#include "/src/libplist/include/plist/plist.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there is at least some data to work with.

    // Initialize plist_t object
    plist_t plist = plist_new_dict();

    // Use the input data to create a key-value pair
    char key[256];
    snprintf(key, sizeof(key), "key_%zu", size); // Create a key based on the size of input data

    // Create a string from the input data
    char *value = static_cast<char*>(malloc(size + 1));
    if (!value) {
        plist_free(plist);
        return 0;
    }
    memcpy(value, data, size);
    value[size] = '\0'; // Null-terminate the string

    // Set the key-value pair in the plist
    plist_dict_set_item(plist, key, plist_new_string(value));

    // Allocate memory for the key-value output
    char *key_val = static_cast<char*>(malloc(256)); // Allocate 256 bytes for key_val.
    if (!key_val) {
        free(value);
        plist_free(plist);
        return 0;
    }

    // Call the function-under-test
    plist_get_key_val(plist, &key_val);

    // Free allocated resources
    free(key_val);
    free(value);
    plist_free(plist);

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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
