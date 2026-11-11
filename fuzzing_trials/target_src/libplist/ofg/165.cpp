extern "C" {
#include <plist/plist.h>
}

#include <cstring> // Include for memcpy

extern "C" int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Initialize plist_t variables
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Convert input data to a null-terminated string for key names
    char key1[256] = {0}; // Ensure the buffer is large enough
    char key2[256] = {0}; // Ensure the buffer is large enough

    if (size > 0) {
        size_t key1_len = size < 255 ? size : 255; // Limit to buffer size
        memcpy(key1, data, key1_len);
        key1[key1_len] = '\0'; // Null-terminate

        // Use second half of data for key2 if possible
        if (size > key1_len + 1) {
            size_t key2_len = size - key1_len - 1 < 255 ? size - key1_len - 1 : 255;
            memcpy(key2, data + key1_len + 1, key2_len);
            key2[key2_len] = '\0'; // Null-terminate
        }
    }

    // Populate source_dict with some data for testing
    plist_dict_set_item(source_dict, "test_key", plist_new_string("test_value"));

    // Call the function-under-test
    plist_err_t result = plist_dict_copy_data(source_dict, dest_dict, key1, key2);

    // Clean up
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

    LLVMFuzzerTestOneInput_165(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
