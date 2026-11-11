// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_string at plist.c:569:9 in plist.h
// plist_get_string_ptr at plist.c:1770:13 in plist.h
// plist_get_string_val at plist.c:1756:6 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_set_string_val at plist.c:2021:6 in plist.h
// plist_string_val_compare_with_size at plist.c:2233:5 in plist.h
// plist_string_val_contains at plist.c:2242:5 in plist.h
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
#include <cstddef>
#include <cstring>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure null-terminated string for plist_new_string
    char *inputStr = new char[Size + 1];
    memcpy(inputStr, Data, Size);
    inputStr[Size] = '\0';

    // Create a new PLIST_STRING node
    plist_t node = plist_new_string(inputStr);

    // Test plist_get_string_ptr
    uint64_t length = 0;
    const char *stringPtr = plist_get_string_ptr(node, &length);

    // Test plist_get_string_val
    char *retrievedVal = nullptr;
    plist_get_string_val(node, &retrievedVal);
    if (retrievedVal) {
        plist_mem_free(retrievedVal);
    }

    // Test plist_set_string_val
    plist_set_string_val(node, "new value");

    // Test plist_string_val_compare_with_size
    plist_string_val_compare_with_size(node, "compare", 7);

    // Test plist_string_val_contains
    plist_string_val_contains(node, "value");

    // Clean up
    plist_free(node);
    delete[] inputStr;

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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    