// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_array at plist.c:538:9 in plist.h
// plist_new_array at plist.c:538:9 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_array_get_size at plist.c:953:10 in plist.h
// plist_array_insert_item at plist.c:1100:6 in plist.h
// plist_array_get_size at plist.c:953:10 in plist.h
// plist_array_get_item_index at plist.c:978:10 in plist.h
// plist_array_new_iter at plist.c:1156:6 in plist.h
// plist_array_free_iter at plist.c:1184:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <climits>
#include "plist.h"

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    // Prepare a new plist array
    plist_t array = plist_new_array();
    if (!array) {
        return 0;
    }

    // Create a new item to insert
    plist_t item = plist_new_array(); // Using plist_new_array() to create a dummy item
    if (!item) {
        plist_free(array);
        return 0;
    }

    // Insert item at random position if possible
    if (Size > 0) {
        uint32_t position = Data[0] % (plist_array_get_size(array) + 1);
        plist_array_insert_item(array, item, position);
    }

    // Get size of the array
    uint32_t size = plist_array_get_size(array);

    // Retrieve index of the item
    uint32_t index = plist_array_get_item_index(item);

    // Create an iterator for the array
    plist_array_iter iter = nullptr;
    plist_array_new_iter(array, &iter);

    // Free the iterator if it was created
    if (iter) {
        plist_array_free_iter(iter);
    }

    // Clean up
    plist_free(array);

    // Note: Do not free the item separately after inserting into the array
    // as it is managed by the array itself.

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    