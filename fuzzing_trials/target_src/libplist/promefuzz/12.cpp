// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_bool at plist.c:588:9 in plist.h
// plist_bool_val_is_true at plist.c:2068:5 in plist.h
// plist_get_bool_val at plist.c:1783:6 in plist.h
// plist_set_bool_val at plist.c:2026:6 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_dict_set_item at plist.c:1314:6 in plist.h
// plist_dict_get_bool at plist.c:1453:9 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_dict_copy_bool at plist.c:1592:13 in plist.h
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
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new boolean plist node
    uint8_t bool_val = Data[0] % 2; // Ensure boolean value is 0 or 1
    plist_t bool_node = plist_new_bool(bool_val);

    // Check if the boolean value is true
    int is_true = plist_bool_val_is_true(bool_node);

    // Retrieve the boolean value
    uint8_t retrieved_val = 0;
    plist_get_bool_val(bool_node, &retrieved_val);

    // Modify the boolean value
    uint8_t new_val = (Data[0] + 1) % 2;
    plist_set_bool_val(bool_node, new_val);

    // Create a dictionary and add the boolean node
    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "test_key", bool_node);

    // Retrieve the boolean value using the key
    uint8_t dict_bool_val = plist_dict_get_bool(dict, "test_key");

    // Create another dictionary for copying
    plist_t target_dict = plist_new_dict();

    // Attempt to copy the boolean value to the target dictionary
    plist_err_t copy_result = plist_dict_copy_bool(target_dict, dict, "test_key", nullptr);

    // Clean up
    plist_free(dict);
    plist_free(target_dict);

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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    