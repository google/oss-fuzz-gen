#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "/src/libplist/include/plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    // Declare and initialize plist_t variable
    plist_t plist = plist_new_dict();

    // Ensure size is large enough to create a string
    if (size == 0) {
        plist_free(plist);
        return 0;
    }

    // Create a null-terminated string from the input data
    char *key = (char *)malloc(size + 1);
    if (key == NULL) {
        plist_free(plist);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0';

    // Add a key-value pair to the plist to ensure plist_key_val_contains has something to search for
    plist_dict_set_item(plist, key, plist_new_string("value"));

    // Call the function-under-test with a key that is guaranteed to be in the plist
    int result = plist_key_val_contains(plist, key);

    // To maximize code coverage, also test with a key that is not in the plist
    char *non_existing_key = "non_existing_key";
    int result_non_existing = plist_key_val_contains(plist, non_existing_key);

    // Free allocated resources
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

    LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
