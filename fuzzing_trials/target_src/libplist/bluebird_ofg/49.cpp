#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid string
    if (size < 2) {
        return 0;
    }

    // Initialize a plist object
    plist_t plist = plist_new_dict();

    // Use a part of the data as a key
    size_t key_length = size / 2;
    char *key = (char *)malloc(key_length + 1);
    if (key == NULL) {
        plist_free(plist);
        return 0;
    }
    memcpy(key, data, key_length);
    key[key_length] = '\0'; // Null-terminate the key string

    // Use the remaining data as a value
    size_t value_length = size - key_length;
    char *value = (char *)malloc(value_length + 1);
    if (value == NULL) {
        free(key);
        plist_free(plist);
        return 0;
    }
    memcpy(value, data + key_length, value_length);
    value[value_length] = '\0'; // Null-terminate the value string

    // Add the key-value pair to the plist
    plist_dict_set_item(plist, key, plist_new_string(value));

    // Call the function-under-test
    int result = plist_key_val_contains(plist, key);

    // Clean up
    free(key);
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
