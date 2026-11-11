#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a meaningful test
    if (size < 2) {
        return 0;
    }

    // Initialize plist_t
    plist_t plist = plist_new_dict();

    // Use the input data to create a key-value pair in the plist
    // The first byte of data is used as the length of the key
    size_t key_length = data[0] % size;
    if (key_length == 0) {
        key_length = 1; // Ensure there's at least one character in the key
    }

    // Ensure the key length does not exceed the size of the data
    if (key_length >= size) {
        key_length = size - 1;
    }

    // Create a key from the input data
    char *key = (char *)malloc(key_length + 1);
    if (!key) {
        plist_free(plist);
        return 0;
    }
    memcpy(key, data + 1, key_length);
    key[key_length] = '\0';

    // Use the rest of the data as the value
    char *value = (char *)malloc(size - key_length);
    if (!value) {
        free(key);
        plist_free(plist);
        return 0;
    }
    memcpy(value, data + 1 + key_length, size - key_length - 1);
    value[size - key_length - 1] = '\0';

    // Set the key-value pair in the plist
    plist_dict_set_item(plist, key, plist_new_string(value));

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
