#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    plist_t dict = NULL;
    char *key = NULL;
    char *value = NULL;

    // Ensure the size is sufficient to create a key and value
    if (size < 2) {
        return 0;
    }

    // Create a plist dictionary
    dict = plist_new_dict();

    // Allocate memory for the key and ensure it's null-terminated
    key = (char *)malloc(size / 2 + 1);
    if (!key) {
        plist_free(dict);
        return 0;
    }
    memcpy(key, data, size / 2);
    key[size / 2] = '\0';

    // Allocate memory for the value and ensure it's null-terminated
    value = (char *)malloc(size / 2 + 1);
    if (!value) {
        free(key);
        plist_free(dict);
        return 0;
    }
    memcpy(value, data + size / 2, size / 2);
    value[size / 2] = '\0';

    // Add an item to the dictionary
    plist_dict_set_item(dict, key, plist_new_string(value));

    // Call the function-under-test
    plist_dict_remove_item(dict, key);

    // Clean up
    free(key);
    free(value);
    plist_free(dict);

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
