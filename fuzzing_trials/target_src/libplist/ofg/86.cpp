#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    #include <stdlib.h> // Include the standard library for malloc and free

    plist_err_t plist_dict_copy_int(plist_t, plist_t, const char *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to create meaningful strings
    }

    // Create two plist objects
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Split the input data into two parts for key and dest_key
    size_t key_len = size / 2;
    size_t dest_key_len = size - key_len;

    // Ensure the strings are null-terminated
    char *key = (char *)malloc(key_len + 1);
    char *dest_key = (char *)malloc(dest_key_len + 1);

    if (!key || !dest_key) {
        // Memory allocation failed
        if (key) free(key);
        if (dest_key) free(dest_key);
        plist_free(source_dict);
        plist_free(dest_dict);
        return 0;
    }

    memcpy(key, data, key_len);
    key[key_len] = '\0';

    memcpy(dest_key, data + key_len, dest_key_len);
    dest_key[dest_key_len] = '\0';

    // Call the function-under-test
    plist_dict_copy_int(source_dict, dest_dict, key, dest_key);

    // Cleanup
    free(key);
    free(dest_key);
    plist_free(source_dict);
    plist_free(dest_dict);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
