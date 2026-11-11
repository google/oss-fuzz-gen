// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_array at plist.c:538:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_array_insert_item at plist.c:1100:6 in plist.h
// plist_array_get_size at plist.c:953:10 in plist.h
// plist_array_get_item at plist.c:963:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_array_set_item at plist.c:1042:6 in plist.h
// plist_array_get_item_index at plist.c:978:10 in plist.h
// plist_array_remove_item at plist.c:1121:6 in plist.h
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

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy PLIST_ARRAY node
    plist_t array_node = plist_new_array();

    // Create a dummy item node
    plist_t item_node = plist_new_string("dummy_item");

    // Insert item_node into array_node at index 0
    plist_array_insert_item(array_node, item_node, 0);

    // Get the size of the array
    uint32_t array_size = plist_array_get_size(array_node);

    // Try to get the item at index 0
    plist_t retrieved_item = plist_array_get_item(array_node, 0);

    // Try to set a new item at index 0
    plist_t new_item_node = plist_new_string("new_dummy_item");
    plist_array_set_item(array_node, new_item_node, 0);

    // Get the index of the new item
    uint32_t item_index = plist_array_get_item_index(new_item_node);

    // Remove the item at index 0
    plist_array_remove_item(array_node, 0);

    // Clean up
    plist_free(array_node);
    // No need to free retrieved_item or new_item_node as they are managed by the array

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    