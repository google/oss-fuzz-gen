#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize a plist object from the input data
    plist_t plist = NULL;

    // Ensure the data is not empty
    if (size > 0) {
        // Create a plist from the input data
        plist_from_bin((const char *)data, size, &plist);

        // Check if the plist is an array
        if (plist && plist_get_node_type(plist) == PLIST_ARRAY) {
            // Get the first item in the array
            plist_t item = plist_array_get_item(plist, 0);

            // Call the function-under-test
            uint32_t index = plist_array_get_item_index(item);

            // Use the index in some way to avoid compiler optimizations removing the call
            if (index != UINT32_MAX) {
                // Do something with the index, e.g., print it (not required)
            }
        }

        // Free the plist object
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
