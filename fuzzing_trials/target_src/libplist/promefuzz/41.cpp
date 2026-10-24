// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_data at plist.c:653:9 in plist.h
// plist_set_data_val at plist.c:2051:6 in plist.h
// plist_get_data_ptr at plist.c:1846:13 in plist.h
// plist_get_data_val at plist.c:1836:6 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_data_val_compare_with_size at plist.c:2295:5 in plist.h
// plist_data_val_compare at plist.c:2278:5 in plist.h
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
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a plist node of type PLIST_DATA
    plist_t node = plist_new_data((const char*)Data, Size);

    // Fuzz plist_set_data_val
    plist_set_data_val(node, (const char*)Data, Size);

    // Fuzz plist_get_data_ptr
    uint64_t length = 0;
    const char* data_ptr = plist_get_data_ptr(node, &length);

    // Fuzz plist_get_data_val
    char* val = nullptr;
    uint64_t val_length = 0;
    plist_get_data_val(node, &val, &val_length);
    if (val) {
        plist_mem_free(val);
    }

    // Prepare a comparison value
    size_t cmp_size = Size / 2;
    const uint8_t* cmpval = Data + cmp_size;

    // Fuzz plist_data_val_compare_with_size
    int cmp_result = plist_data_val_compare_with_size(node, cmpval, cmp_size);

    // Fuzz plist_data_val_compare
    cmp_result = plist_data_val_compare(node, cmpval, cmp_size);

    // Cleanup
    plist_free(node);

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    