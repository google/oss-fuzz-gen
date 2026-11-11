#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Wrap the C library includes in extern "C"
extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize a plist object
    plist_t plist = plist_new_array();

    // Use the input data to create plist items
    size_t offset = 0;
    while (offset < size) {
        // Create a string from the data
        size_t len = (size - offset > 10) ? 10 : size - offset; // Limit string length to 10
        char *str = (char *)malloc(len + 1);
        memcpy(str, data + offset, len);
        str[len] = '\0';

        // Add the string as a new item in the plist array
        plist_t item = plist_new_string(str);
        plist_array_append_item(plist, item);

        // Clean up
        free(str);
        offset += len;
    }

    // Call the function-under-test
    // Correct usage of plist_array_item_remove with a single argument
    if (plist_array_get_size(plist) > 0) {
        plist_t first_item = plist_array_get_item(plist, 0);
        plist_array_item_remove(first_item);
    }

    // Free the plist object
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
