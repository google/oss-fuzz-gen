// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// array_list_new at arraylist.c:39:20 in arraylist.h
// array_list_free at arraylist.c:64:13 in arraylist.h
// array_list_insert_idx at arraylist.c:128:5 in arraylist.h
// array_list_free at arraylist.c:64:13 in arraylist.h
// array_list_put_idx at arraylist.c:150:5 in arraylist.h
// array_list_get_idx at arraylist.c:74:7 in arraylist.h
// array_list_length at arraylist.c:201:8 in arraylist.h
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
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "arraylist.h"

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) {
        return 0;
    }

    struct array_list *al = array_list_new(NULL);
    if (!al) {
        return 0;
    }

    size_t idx = 0;
    while (idx + sizeof(size_t) <= Size) {
        size_t i = *(size_t *)(Data + idx);
        idx += sizeof(size_t);

        if (idx < Size) {
            void *data = malloc(1); // Allocate a byte for simplicity
            if (!data) {
                array_list_free(al);
                return 0;
            }

            int insert_result = array_list_insert_idx(al, i, data);
            if (insert_result != 0) {
                free(data);
            }
        }

        if (idx + sizeof(void *) <= Size) {
            void *data = malloc(1); // Allocate a byte for simplicity
            if (!data) {
                array_list_free(al);
                return 0;
            }
            memcpy(data, Data + idx, 1);
            array_list_put_idx(al, i, data);
            idx += 1;
        }

        if (idx < Size) {
            void *element = array_list_get_idx(al, i);
            // Use the element in some way, e.g., by casting and reading its value
            (void)element;
        }

        size_t length = array_list_length(al);
        (void)length; // Use the length in some way

        if (idx < Size) {
            int shrink_result = array_list_shrink(al, (size_t)Data[idx]);
            (void)shrink_result; // Use the result in some way
            idx++;
        }
    }

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

        LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    