extern "C" {
#include <plist/plist.h>
#include <stdlib.h>
#include <string.h>
}

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Initialize a plist_t object
    plist_t plist = plist_new_dict();

    // Add a boolean key-value pair to the plist
    plist_dict_set_item(plist, "test_key", plist_new_bool(1));

    // Ensure the data size is non-zero and not too large for a key
    if (size > 0 && size < 256) {
        // Convert the data to a null-terminated string for use as a key
        char *key = (char *)malloc(size + 1);
        if (key == NULL) {
            plist_free(plist);
            return 0;
        }
        memcpy(key, data, size);
        key[size] = '\0';

        // Call the function-under-test
        uint8_t result = plist_dict_get_bool(plist, key);

        // Clean up
        free(key);
    }

    // Free the plist object
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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
