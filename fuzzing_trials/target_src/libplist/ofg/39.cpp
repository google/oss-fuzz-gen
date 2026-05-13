#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "/src/libplist/include/plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Create a plist_t object
    plist_t plist = plist_new_dict();  // Assuming plist_new_dict() creates a new dictionary plist

    // Prepare a null-terminated string from the fuzz input
    char *key = (char *)malloc(size + 1);
    if (key == NULL) {
        plist_free(plist);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0';

    // Add a key-value pair to the plist using the fuzz input as the key
    plist_dict_set_item(plist, key, plist_new_string("test_value"));

    // Call the function-under-test with a known key
    int result = plist_key_val_compare(plist, key);

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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
