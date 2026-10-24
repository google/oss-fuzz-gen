#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    // Initialize a plist_t object
    plist_t plist = plist_new_dict();

    // Ensure that size is sufficient to create a non-empty key
    if (size == 0) {
        plist_free(plist);
        return 0;
    }

    // Create a key for the dictionary
    char *key = (char *)malloc(size + 1);
    if (!key) {
        plist_free(plist);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0'; // Null-terminate the string

    // Add a dummy item to the dictionary with the key
    plist_dict_set_item(plist, key, plist_new_string("dummy_value"));

    // Call the function-under-test
    plist_dict_remove_item(plist, key);

    // Clean up
    free(key);
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

    LLVMFuzzerTestOneInput_177(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
