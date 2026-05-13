#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Create a plist object
    plist_t plist = plist_new_dict();

    // Add some dummy key-value pairs to the plist
    plist_dict_set_item(plist, "key1", plist_new_uint(42));
    plist_dict_set_item(plist, "key2", plist_new_uint(100));
    plist_dict_set_item(plist, "key3", plist_new_uint(999));

    // Ensure the data is null-terminated for safe string operations
    char *key = (char *)malloc(size + 1);
    if (key == NULL) {
        plist_free(plist);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0';

    // Call the function-under-test
    uint64_t value = plist_dict_get_uint(plist, key);

    // Print the value for debugging purposes (optional)
    // printf("Key: %s, Value: %" PRIu64 "\n", key, value);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
