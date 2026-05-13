// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_dict_get_item_key at plist.c:1254:6 in plist.h
// plist_get_key_val at plist.c:1742:6 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_dict_remove_item at plist.c:1411:6 in plist.h
// plist_dict_get_item at plist.c:1274:9 in plist.h
// plist_dict_copy_int at plist.c:1602:13 in plist.h
// plist_set_key_val at plist.c:2011:6 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_dict_set_item at plist.c:1314:6 in plist.h
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
extern "C" {
#include <plist/plist.h>
}

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>

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

static void fuzz_plist_dict_remove_item(plist_t node) {
    const char *key = "dummy_key";
    plist_dict_remove_item(node, key);
}

static void fuzz_plist_dict_get_item(plist_t node) {
    const char *key = "dummy_key";
    plist_t item = plist_dict_get_item(node, key);
    // No need to free item as per documentation
}

static void fuzz_plist_dict_copy_int(plist_t target_dict, plist_t source_dict) {
    const char *key = "dummy_key";
    const char *alt_key = "alt_dummy_key";
    plist_err_t err = plist_dict_copy_int(target_dict, source_dict, key, alt_key);
    assert(err == PLIST_ERR_SUCCESS || err == PLIST_ERR_INVALID_ARG);
}

static void fuzz_plist_set_key_val(plist_t node) {
    const char *val = "dummy_key_value";
    plist_set_key_val(node, val);
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    // Create a dummy plist node for testing
    plist_t dict = plist_new_dict();
    plist_t item = plist_new_string("dummy_value");

    plist_dict_set_item(dict, "dummy_key", item);

    // Fuzz each function
    fuzz_plist_dict_get_item_key(item);
    fuzz_plist_get_key_val(item);
    fuzz_plist_dict_get_item(dict);
    fuzz_plist_dict_copy_int(dict, dict);
    fuzz_plist_set_key_val(item);

    // Remove item before freeing dict to avoid use-after-free
    fuzz_plist_dict_remove_item(dict);

    // Clean up
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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    