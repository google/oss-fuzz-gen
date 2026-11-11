#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Call the function-under-test
    plist_t dict = plist_new_dict();

    // Perform operations on the created plist dictionary if needed
    // For example, adding some dummy data to the dictionary
    if (dict != NULL && size > 0) {
        // Create a key-value pair and add it to the dictionary
        plist_t key = plist_new_string("key");
        plist_t value = plist_new_data((const char*)data, size);
        plist_dict_set_item(dict, "key", value);
    }

    // Clean up
    if (dict != NULL) {
        plist_free(dict);
    }

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
