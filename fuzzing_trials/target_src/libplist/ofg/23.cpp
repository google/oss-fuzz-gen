#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    #include <stdlib.h>
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Initialize a plist dictionary
    plist_t dict = plist_new_dict();

    // Add some key-value pairs to the dictionary
    plist_dict_set_item(dict, "key1", plist_new_string("value1"));
    plist_dict_set_item(dict, "key2", plist_new_string("value2"));
    plist_dict_set_item(dict, "key3", plist_new_string("value3"));

    // Ensure the data is null-terminated for string usage
    char *key = (char *)malloc(size + 1);
    if (key == NULL) {
        plist_free(dict);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0';

    // Call the function-under-test
    plist_t item = plist_dict_get_item(dict, key);

    // Clean up
    plist_free(dict);
    free(key);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
