extern "C" {
    #include <plist/plist.h>
}

#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure that the data is large enough to be split into meaningful parts
    if (size < 3) return 0;

    // Create a root plist dictionary
    plist_t root_dict = plist_new_dict();

    // Create a key from the input data
    size_t key_length = size / 3;
    char *key = new char[key_length + 1];
    memcpy(key, data, key_length);
    key[key_length] = '\0'; // Null-terminate the key string

    // Create a value plist node from the input data
    size_t value_data_length = size - key_length;
    plist_t value_node = plist_new_data((const char *)(data + key_length), value_data_length);

    // Call the function-under-test
    plist_dict_set_item(root_dict, key, value_node);

    // Clean up
    delete[] key;
    plist_free(root_dict);

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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
