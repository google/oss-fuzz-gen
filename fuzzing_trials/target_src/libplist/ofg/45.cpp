#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Initialize plist_t
    plist_t plist = plist_new_dict();

    // Create a key-value pair in the plist dictionary
    char key[] = "example_key";
    plist_dict_set_item(plist, key, plist_new_string("example_value"));

    // Ensure the size is enough for a key
    if (size < 1) {
        plist_free(plist);
        return 0;
    }

    // Allocate memory for the key buffer
    char *key_buffer = static_cast<char*>(malloc(size + 1));
    if (!key_buffer) {
        plist_free(plist);
        return 0;
    }

    // Copy data to key_buffer and null-terminate it
    memcpy(key_buffer, data, size);
    key_buffer[size] = '\0';

    // Call the function-under-test
    plist_dict_get_item_key(plist, &key_buffer);

    // Free allocated resources
    free(key_buffer);
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
