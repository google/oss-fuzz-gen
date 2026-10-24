#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract a uint32_t index
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a plist array with some dummy data
    plist_t plist = plist_new_array();
    for (uint32_t i = 0; i < 10; ++i) {
        plist_t item = plist_new_uint(i);
        plist_array_append_item(plist, item);
    }

    // Extract a uint32_t index from the input data
    uint32_t index = *((uint32_t *)data);

    // Call the function-under-test
    plist_array_remove_item(plist, index);

    // Free the plist to avoid memory leaks
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
