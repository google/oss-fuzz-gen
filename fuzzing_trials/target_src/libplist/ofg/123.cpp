extern "C" {
    #include <plist/plist.h>
    #include <stdlib.h>
    #include <string.h>
}

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    if (size < 2) {
        // Not enough data to create meaningful inputs
        return 0;
    }

    // Initialize the plist objects
    plist_t dict = plist_new_dict();
    plist_t value = plist_new_string("example_value");

    // Use part of the data as the key
    size_t key_length = size / 2;
    char *key = (char *)malloc(key_length + 1);
    if (!key) {
        plist_free(dict);
        plist_free(value);
        return 0;
    }
    memcpy(key, data, key_length);
    key[key_length] = '\0';

    // Call the function-under-test
    plist_dict_set_item(dict, key, value);

    // Clean up
    free(key);
    plist_free(dict);
    // Note: Do not free 'value' as plist_dict_set_item takes ownership of it

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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
