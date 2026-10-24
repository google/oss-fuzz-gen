// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_dict_get_item_key at plist.c:1254:6 in plist.h
// plist_get_key_val at plist.c:1742:6 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_dict_remove_item at plist.c:1411:6 in plist.h
// plist_dict_get_item at plist.c:1274:9 in plist.h
// plist_dict_copy_int at plist.c:1602:13 in plist.h
// plist_set_key_val at plist.c:2011:6 in plist.h
// plist_from_memory at plist.c:225:13 in plist.h
// plist_get_node_type at plist.c:1731:12 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_free at plist.c:712:6 in plist.h
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
#include <fstream>
#include "plist/plist.h"

static void fuzz_plist_dict_get_item_key(plist_t node) {
    char *key = nullptr;
    plist_dict_get_item_key(node, &key);
    if (key) {
        free(key);
    }
}

static void fuzz_plist_get_key_val(plist_t node) {
    char *val = nullptr;
    plist_get_key_val(node, &val);
    if (val) {
        plist_mem_free(val);
    }
}

static void fuzz_plist_dict_remove_item(plist_t node, const char *key) {
    plist_dict_remove_item(node, key);
}

static void fuzz_plist_dict_get_item(plist_t node, const char *key) {
    plist_t item = plist_dict_get_item(node, key);
    // No need to free the returned item as per the documentation.
}

static void fuzz_plist_dict_copy_int(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_key) {
    plist_dict_copy_int(target_dict, source_dict, key, alt_key);
}

static void fuzz_plist_set_key_val(plist_t node, const char *val) {
    plist_set_key_val(node, val);
}

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    plist_t dict = nullptr;
    plist_format_t format;
    plist_from_memory(reinterpret_cast<const char*>(Data), Size, &dict, &format);

    if (plist_get_node_type(dict) != PLIST_DICT) {
        plist_free(dict);
        return 0;
    }

    // Dummy key for testing
    const char *dummy_key = "dummy_key";

    // Fuzz each function with the dictionary
    fuzz_plist_dict_get_item_key(dict);
    fuzz_plist_get_key_val(dict);
    fuzz_plist_dict_remove_item(dict, dummy_key);
    fuzz_plist_dict_get_item(dict, dummy_key);

    // Create another dictionary for copy testing
    plist_t target_dict = plist_new_dict();
    fuzz_plist_dict_copy_int(target_dict, dict, dummy_key, nullptr);

    // Create a new node for set key value testing
    plist_t node = plist_new_dict();
    fuzz_plist_set_key_val(node, dummy_key);

    // Cleanup
    plist_free(dict);
    plist_free(target_dict);
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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    