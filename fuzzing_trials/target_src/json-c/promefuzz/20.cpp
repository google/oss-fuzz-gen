// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// array_list_new2 at arraylist.c:44:20 in arraylist.h
// array_list_insert_idx at arraylist.c:128:5 in arraylist.h
// array_list_put_idx at arraylist.c:150:5 in arraylist.h
// array_list_del_idx at arraylist.c:206:5 in arraylist.h
// array_list_shrink at arraylist.c:106:5 in arraylist.h
// array_list_free at arraylist.c:64:13 in arraylist.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "arraylist.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void dummy_free(void* data) {
    // Dummy free function for array_list_new2
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new array list with a random initial size
    int initial_size = Data[0] % 10; // Keep initial size small
    struct array_list* al = array_list_new2(dummy_free, initial_size);
    if (!al) return 0;

    // Insert data into the array list
    for (size_t i = 1; i < Size; ++i) {
        // Use array_list_insert_idx to insert data
        int insert_result = array_list_insert_idx(al, i - 1, (void*)&Data[i]);
        if (insert_result == -1) {
            // If insert fails, use array_list_put_idx
            array_list_put_idx(al, i - 1, (void*)&Data[i]);
        }
    }

    // Try deleting elements from random indices
    if (Size > 2) {
        size_t idx = Data[1] % Size;
        size_t count = Data[2] % (Size - idx);
        array_list_del_idx(al, idx, count);
    }

    // Shrink the array list
    array_list_shrink(al, 2);

    // Free the array list
    array_list_free(al);

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    