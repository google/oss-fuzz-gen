// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_string at plist.c:569:9 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_dict_set_item at plist.c:1314:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_string_val_compare at plist.c:2224:5 in plist.h
// plist_key_val_compare at plist.c:2251:5 in plist.h
// plist_string_val_compare_with_size at plist.c:2233:5 in plist.h
// plist_key_val_compare_with_size at plist.c:2260:5 in plist.h
// plist_key_val_contains at plist.c:2269:5 in plist.h
// plist_compare_node_value at plist.c:1949:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
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
#include <cstring>
#include "plist.h"

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create dummy PLIST_STRING and PLIST_KEY nodes
    plist_t string_node = plist_new_string("dummy_string");
    plist_t key_node = plist_new_dict(); // Create a dictionary node
    plist_dict_set_item(key_node, "dummy_key", plist_new_string("dummy_value"));

    // Prepare a comparison string from the input data
    char *cmpval = static_cast<char*>(malloc(Size + 1));
    if (!cmpval) {
        plist_free(string_node);
        plist_free(key_node);
        return 0;
    }
    memcpy(cmpval, Data, Size);
    cmpval[Size] = '\0';

    // Use the first byte of data as a size limit for functions with size parameter
    size_t n = static_cast<size_t>(Data[0]);

    // Fuzz plist_string_val_compare
    plist_string_val_compare(string_node, cmpval);

    // Fuzz plist_key_val_compare
    plist_key_val_compare(key_node, cmpval);

    // Fuzz plist_string_val_compare_with_size
    plist_string_val_compare_with_size(string_node, cmpval, n);

    // Fuzz plist_key_val_compare_with_size
    plist_key_val_compare_with_size(key_node, cmpval, n);

    // Fuzz plist_key_val_contains
    plist_key_val_contains(key_node, cmpval);

    // Fuzz plist_compare_node_value
    plist_compare_node_value(string_node, key_node);

    // Clean up
    free(cmpval);
    plist_free(string_node);
    plist_free(key_node);

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    