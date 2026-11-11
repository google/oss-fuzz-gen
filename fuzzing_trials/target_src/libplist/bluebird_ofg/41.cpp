#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating meaningful strings
    if (size < 2) return 0;

    // Create two plist objects
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Create two strings from the input data
    size_t half_size = size / 2;
    char *key = (char *)malloc(half_size + 1);
    char *value = (char *)malloc(size - half_size + 1);

    if (key == NULL || value == NULL) {
        free(key);
        free(value);
        plist_free(source_dict);
        plist_free(dest_dict);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(key, data, half_size);
    key[half_size] = '\0';
    memcpy(value, data + half_size, size - half_size);
    value[size - half_size] = '\0';

    // Add the key-value pair to the source dictionary
    plist_dict_set_item(source_dict, key, plist_new_string(value));

    // Call the function-under-test
    plist_err_t result = plist_dict_copy_string(dest_dict, source_dict, key, key);

    // Clean up
    free(key);
    free(value);
    plist_free(source_dict);
    plist_free(dest_dict);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
