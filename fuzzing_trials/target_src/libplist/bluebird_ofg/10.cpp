#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for malloc and free
#include <string.h>  // Include for memcpy
#include "plist/plist.h"

extern "C" {
    // Function signature from the library
    plist_err_t plist_dict_copy_bool(plist_t dest, plist_t src, const char *dest_key, const char *src_key);
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create meaningful keys
    if (size < 2) {
        return 0;
    }

    // Create two plist dictionaries
    plist_t src_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Use the first byte of data as a boolean value
    bool bool_value = (data[0] % 2 == 0);

    // Add a boolean value to the source dictionary with a fixed key
    const char *src_key = "source_key";
    plist_dict_set_item(src_dict, src_key, plist_new_bool(bool_value));

    // Use the remaining data to form the source and destination keys
    size_t key_size = (size - 1) / 2;
    char *src_key_dynamic = (char *)malloc(key_size + 1);
    char *dest_key_dynamic = (char *)malloc(key_size + 1);

    if (src_key_dynamic == NULL || dest_key_dynamic == NULL) {
        plist_free(src_dict);
        plist_free(dest_dict);
        free(src_key_dynamic);
        free(dest_key_dynamic);
        return 0;
    }

    // Ensure null-terminated strings
    memcpy(src_key_dynamic, data + 1, key_size);
    src_key_dynamic[key_size] = '\0';
    memcpy(dest_key_dynamic, data + 1 + key_size, key_size);
    dest_key_dynamic[key_size] = '\0';

    // Call the function-under-test
    plist_dict_copy_bool(dest_dict, src_dict, dest_key_dynamic, src_key_dynamic);

    // Clean up
    plist_free(src_dict);
    plist_free(dest_dict);
    free(src_key_dynamic);
    free(dest_key_dynamic);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
