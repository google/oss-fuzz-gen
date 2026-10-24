extern "C" {
#include <plist/plist.h>
}

#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Ensure there's enough data for both plist and key
    }

    // Initialize a plist
    plist_t plist = plist_new_dict();

    // Create a key-value pair in the plist
    const char *key = "test_key";
    plist_dict_set_item(plist, key, plist_new_string("test_value"));

    // Use part of the input data as the key
    size_t key_length = size - 1;
    char *fuzz_key = new char[key_length + 1];
    memcpy(fuzz_key, data, key_length);
    fuzz_key[key_length] = '\0';

    // Call the function under test
    int result = plist_key_val_compare(plist, fuzz_key);

    // Clean up
    delete[] fuzz_key;
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
