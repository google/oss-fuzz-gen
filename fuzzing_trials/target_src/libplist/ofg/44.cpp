#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Initialize plist_t object
    plist_t plist = plist_new_dict();

    // Create a dummy key-value pair in the plist
    plist_dict_set_item(plist, "dummy_key", plist_new_string("dummy_value"));

    // Allocate memory for the key
    char *key = (char *)malloc(size + 1);
    if (!key) {
        plist_free(plist);
        return 0;
    }

    // Copy data to key and ensure null-termination
    memcpy(key, data, size);
    key[size] = '\0';

    // Call the function-under-test
    plist_t item = plist_dict_get_item(plist, key);

    // Check if the item is not null to simulate usage
    if (item) {
        char *value = NULL;
        plist_get_string_val(item, &value);
        if (value) {
            free(value);
        }
    }

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
