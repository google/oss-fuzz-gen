#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    plist_err_t plist_dict_copy_data(plist_t, plist_t, const char *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Create two plist objects
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Use the first byte of data as a key for source_dict
    char source_key[2] = {0};
    source_key[0] = data[0];

    // Use the second byte of data as a key for dest_dict
    char dest_key[2] = {0};
    dest_key[0] = data[1];

    // Add some data to the source_dict
    plist_dict_set_item(source_dict, source_key, plist_new_string("test_value"));

    // Call the function-under-test
    plist_err_t result = plist_dict_copy_data(dest_dict, source_dict, dest_key, source_key);

    // Clean up plist objects
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

    LLVMFuzzerTestOneInput_164(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
