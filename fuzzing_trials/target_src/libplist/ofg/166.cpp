#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include the standard library for malloc and free

extern "C" {
    #include <plist/plist.h> // Include the plist library within extern "C"

    plist_err_t plist_dict_copy_uint(plist_t, plist_t, const char *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Initialize source and destination plist
    plist_t src_plist = plist_new_dict();
    plist_t dst_plist = plist_new_dict();

    // Ensure the data size is sufficient for keys
    if (size < 2) {
        plist_free(src_plist);
        plist_free(dst_plist);
        return 0;
    }

    // Use the first half of data as the source key
    size_t key_length = size / 2;
    char *src_key = (char *)malloc(key_length + 1);
    memcpy(src_key, data, key_length);
    src_key[key_length] = '\0';

    // Use the second half of data as the destination key
    size_t dest_key_length = size - key_length;
    char *dest_key = (char *)malloc(dest_key_length + 1);
    memcpy(dest_key, data + key_length, dest_key_length);
    dest_key[dest_key_length] = '\0';

    // Add a sample uint value to the source plist
    plist_dict_set_item(src_plist, src_key, plist_new_uint(42));

    // Call the function-under-test
    plist_dict_copy_uint(src_plist, dst_plist, src_key, dest_key);

    // Clean up
    free(src_key);
    free(dest_key);
    plist_free(src_plist);
    plist_free(dst_plist);

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

    LLVMFuzzerTestOneInput_166(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
