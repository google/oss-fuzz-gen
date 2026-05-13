// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_uint at plist.c:601:9 in plist.h
// plist_set_uint_val at plist.c:2031:6 in plist.h
// plist_get_uint_val at plist.c:1795:6 in plist.h
// plist_get_parent at plist.c:1726:9 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_uid at plist.c:627:9 in plist.h
// plist_set_uid_val at plist.c:2041:6 in plist.h
// plist_get_parent at plist.c:1726:9 in plist.h
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

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0;
    }

    uint64_t val;
    memcpy(&val, Data, sizeof(uint64_t));

    // Test plist_new_uint
    plist_t uint_node = plist_new_uint(val);
    if (uint_node) {
        // Test plist_set_uint_val
        plist_set_uint_val(uint_node, val);

        // Test plist_get_uint_val
        uint64_t retrieved_val = 0;
        plist_get_uint_val(uint_node, &retrieved_val);

        // Test plist_get_parent
        plist_t parent = plist_get_parent(uint_node);

        plist_free(uint_node);
    }

    // Test plist_new_uid
    plist_t uid_node = plist_new_uid(val);
    if (uid_node) {
        // Test plist_set_uid_val
        plist_set_uid_val(uid_node, val);

        // Test plist_get_parent
        plist_t parent = plist_get_parent(uid_node);

        plist_free(uid_node);
    }

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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    