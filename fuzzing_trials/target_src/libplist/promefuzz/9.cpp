// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_from_bin at bplist.c:905:13 in plist.h
// plist_dict_get_item_key at plist.c:1254:6 in plist.h
// plist_dict_get_bool at plist.c:1453:9 in plist.h
// plist_get_key_val at plist.c:1742:6 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_dict_remove_item at plist.c:1411:6 in plist.h
// plist_dict_get_item at plist.c:1274:9 in plist.h
// plist_dict_next_item at plist.c:1215:6 in plist.h
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
#include <plist/plist.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    plist_t plist = nullptr;
    plist_from_bin(reinterpret_cast<const char*>(Data), Size, &plist);

    if (!plist) return 0;

    // Fuzz plist_dict_get_item_key
    char *key = nullptr;
    plist_dict_get_item_key(plist, &key);
    if (key) {
        free(key);
    }

    // Fuzz plist_dict_get_bool
    char dummyKey[] = "dummyKey";
    uint8_t boolValue = plist_dict_get_bool(plist, dummyKey);

    // Fuzz plist_get_key_val
    char *keyVal = nullptr;
    plist_get_key_val(plist, &keyVal);
    if (keyVal) {
        plist_mem_free(keyVal);
    }

    // Fuzz plist_dict_remove_item
    plist_dict_remove_item(plist, dummyKey);

    // Fuzz plist_dict_get_item
    plist_t item = plist_dict_get_item(plist, dummyKey);

    // Fuzz plist_dict_next_item
    plist_dict_iter iter = nullptr;
    char *nextKey = nullptr;
    plist_t nextVal = nullptr;
    plist_dict_next_item(plist, iter, &nextKey, &nextVal);
    if (nextKey) {
        free(nextKey);
    }

    plist_free(plist);
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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    