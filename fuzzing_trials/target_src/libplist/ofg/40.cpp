#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating non-empty strings
    if (size < 4) {
        return 0;
    }

    // Initialize plist_t variables
    plist_t dict1 = plist_new_dict();
    plist_t dict2 = plist_new_dict();

    // Create non-null strings from the input data
    char *key = (char *)malloc(size / 2 + 1);
    char *value = (char *)malloc(size / 2 + 1);

    if (key == NULL || value == NULL) {
        if (key) free(key);
        if (value) free(value);
        plist_free(dict1);
        plist_free(dict2);
        return 0;
    }

    memcpy(key, data, size / 2);
    key[size / 2] = '\0';

    memcpy(value, data + size / 2, size / 2);
    value[size / 2] = '\0';

    // Add a key-value pair to the first dictionary
    plist_dict_set_item(dict1, key, plist_new_string(value));

    // Call the function-under-test
    plist_err_t result = plist_dict_copy_string(dict1, dict2, key, key);

    // Clean up
    free(key);
    free(value);
    plist_free(dict1);
    plist_free(dict2);

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
