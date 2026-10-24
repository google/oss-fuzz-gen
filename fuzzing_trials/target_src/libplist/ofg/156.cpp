#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    // Include the function-under-test
    int plist_key_val_compare_with_size(plist_t plist, const char *key, size_t size);
}

extern "C" int LLVMFuzzerTestOneInput_156(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a key
    if (size < 1) {
        return 0;
    }

    // Create a plist node
    plist_t plist = plist_new_dict();

    // Use the first byte as a key length
    size_t key_length = data[0] % size;
    if (key_length == 0) {
        key_length = 1; // Ensure at least one character for the key
    }

    // Ensure we have enough data for the key
    if (key_length >= size) {
        plist_free(plist);
        return 0;
    }

    // Allocate memory for the key
    char *key = (char *)malloc(key_length + 1);
    if (!key) {
        plist_free(plist);
        return 0;
    }

    // Copy the key from the data
    memcpy(key, data + 1, key_length);
    key[key_length] = '\0'; // Null-terminate the key

    // Call the function-under-test
    plist_key_val_compare_with_size(plist, key, key_length);

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

    LLVMFuzzerTestOneInput_156(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
