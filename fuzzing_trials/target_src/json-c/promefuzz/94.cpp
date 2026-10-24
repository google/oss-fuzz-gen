// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// array_list_new2 at arraylist.c:44:20 in arraylist.h
// array_list_free at arraylist.c:64:13 in arraylist.h
// array_list_insert_idx at arraylist.c:128:5 in arraylist.h
// array_list_free at arraylist.c:64:13 in arraylist.h
// array_list_add at arraylist.c:175:5 in arraylist.h
// array_list_free at arraylist.c:64:13 in arraylist.h
// array_list_put_idx at arraylist.c:150:5 in arraylist.h
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

static void dummy_free(void *data) {
    // Dummy free function for demonstration purposes.
    // Normally, you would free any allocated resources here.
}

extern "C" int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Use the first byte of data to decide initial size for array_list_new2
    int initial_size = Data[0];

    // Create a new array_list using array_list_new2
    struct array_list *al = array_list_new2(dummy_free, initial_size);
    if (!al) {
        return 0;
    }

    // Insert data into the array list at various indices
    for (size_t i = 1; i < Size; ++i) {
        void *data = malloc(1);  // Allocate dummy data
        if (!data) {
            array_list_free(al);
            return 0;
        }

        // Try to insert at index i
        array_list_insert_idx(al, i % (initial_size + 1), data);
    }

    // Add data to the end of the array list
    for (size_t i = 1; i < Size; ++i) {
        void *data = malloc(1);  // Allocate dummy data
        if (!data) {
            array_list_free(al);
            return 0;
        }

        // Try to add data to the end of the list
        array_list_add(al, data);
    }

    // Put data at specific indices
    for (size_t i = 1; i < Size; ++i) {
        void *data = malloc(1);  // Allocate dummy data
        if (!data) {
            array_list_free(al);
            return 0;
        }

        // Try to put data at index i
        array_list_put_idx(al, i % (initial_size + 1), data);
    }

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

        LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    