// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_from_bin at bplist.c:905:13 in plist.h
// plist_get_node_type at plist.c:1731:12 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_dict_next_item at plist.c:1215:6 in plist.h
// plist_dict_get_item_key at plist.c:1254:6 in plist.h
// plist_dict_get_uint at plist.c:1541:10 in plist.h
// plist_dict_remove_item at plist.c:1411:6 in plist.h
// plist_dict_next_item at plist.c:1215:6 in plist.h
// plist_dict_get_size at plist.c:1189:10 in plist.h
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

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    plist_t dict = nullptr;
    plist_from_bin((const char*)Data, Size, &dict);

    if (!dict || plist_get_node_type(dict) != PLIST_DICT) {
        plist_free(dict);
        return 0;
    }

    // Test plist_dict_get_item_key
    plist_dict_iter iter = nullptr;
    char *key = nullptr;
    plist_t val = nullptr;
    plist_dict_next_item(dict, &iter, &key, &val);
    if (key) {
        char *retrieved_key = nullptr;
        plist_dict_get_item_key(val, &retrieved_key);
        if (retrieved_key) {
            free(retrieved_key);
        }
        free(key);
    }

    // Test plist_dict_get_uint
    uint64_t uint_value = plist_dict_get_uint(dict, key);
    (void)uint_value; // Suppress unused variable warning

    // Test plist_dict_remove_item
    if (key) {
        plist_dict_remove_item(dict, key);
    }

    // Test plist_dict_next_item
    iter = nullptr;
    key = nullptr;
    val = nullptr;
    plist_dict_next_item(dict, &iter, &key, &val);
    if (key) {
        free(key);
    }

    // Test plist_dict_get_size
    uint32_t size = plist_dict_get_size(dict);
    (void)size; // Suppress unused variable warning

    plist_free(dict);
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

        LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    