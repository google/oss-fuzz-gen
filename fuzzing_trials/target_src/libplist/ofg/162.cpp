#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Initialize plist_t variables
    plist_t dict1 = NULL;
    plist_t dict2 = NULL;

    // Create two sample dictionaries for merging
    dict1 = plist_new_dict();
    dict2 = plist_new_dict();

    // Ensure dict1 and dict2 are not NULL
    if (dict1 == NULL || dict2 == NULL) {
        if (dict1) plist_free(dict1);
        if (dict2) plist_free(dict2);
        return 0;
    }

    // Add some key-value pairs to dict1 and dict2
    plist_dict_set_item(dict1, "key1", plist_new_string("value1"));
    plist_dict_set_item(dict2, "key2", plist_new_string("value2"));

    // Use the input data to add more entries to dict1 and dict2
    if (size > 0) {
        char key[16];
        snprintf(key, sizeof(key), "key_%u", data[0]);
        plist_dict_set_item(dict1, key, plist_new_string("dynamic_value1"));

        if (size > 1) {
            snprintf(key, sizeof(key), "key_%u", data[1]);
            plist_dict_set_item(dict2, key, plist_new_string("dynamic_value2"));
        }
    }

    // Call the function-under-test
    plist_dict_merge(&dict1, dict2); // Take the address of dict1

    // Clean up
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

    LLVMFuzzerTestOneInput_162(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
