#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // Include for free function

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize a plist object from the input data
    plist_t plist = NULL;
    plist_from_memory((const char*)data, size, &plist, NULL); // Provide NULL for the format argument

    // Create an iterator for the array
    plist_array_iter iter = NULL;
    plist_array_new_iter(plist, &iter);

    // Prepare a variable to hold the next item
    plist_t next_item = NULL;

    // Call the function-under-test
    plist_array_next_item(plist, iter, &next_item);

    // Clean up
    if (next_item != NULL) {
        plist_free(next_item);
    }
    if (iter != NULL) {
        free(iter);
    }
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
