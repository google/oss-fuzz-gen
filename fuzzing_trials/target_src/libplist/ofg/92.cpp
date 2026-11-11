#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 4) {
        return 0;
    }

    // Initialize plist_t variables
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Create some keys and values for the source dictionary
    plist_dict_set_item(source_dict, "key1", plist_new_string("value1"));
    plist_dict_set_item(source_dict, "key2", plist_new_string("value2"));

    // Use the first two bytes of data to determine the keys
    const char *source_key = (const char *)data;
    const char *dest_key = (const char *)(data + 2);

    // Ensure null-termination for keys
    char source_key_buffer[3] = {0};
    char dest_key_buffer[3] = {0};
    memcpy(source_key_buffer, source_key, 2);
    memcpy(dest_key_buffer, dest_key, 2);

    // Call the function-under-test
    plist_err_t result = plist_dict_copy_item(dest_dict, source_dict, source_key_buffer, dest_key_buffer);

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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
