#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Create a plist from the input data
    plist_t plist = NULL;
    plist_format_t format;
    plist_from_memory((const char*)data, size, &plist, &format);

    // Ensure the plist is a dictionary and not NULL
    if (plist != NULL && plist_get_node_type(plist) == PLIST_DICT) {
        // Get the first item in the dictionary
        plist_t item = plist_dict_get_item(plist, "key");

        // Call the function-under-test
        plist_t key = plist_dict_item_get_key(item);

        // Clean up
        if (key != NULL) {
            plist_free(key);
        }
        if (item != NULL) {
            plist_free(item);
        }
    }

    // Free the plist
    if (plist != NULL) {
        plist_free(plist);
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
