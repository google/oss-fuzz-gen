// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_date at plist.c:673:9 in plist.h
// plist_set_date_val at plist.c:2056:6 in plist.h
// plist_set_unix_date_val at plist.c:2062:6 in plist.h
// plist_get_date_val at plist.c:1858:6 in plist.h
// plist_date_val_compare at plist.c:2182:5 in plist.h
// plist_unix_date_val_compare at plist.c:2206:5 in plist.h
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
#include <plist/plist.h>
#include <cstdlib>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2) {
        return 0;
    }

    int32_t sec = 0;
    int32_t usec = 0;
    int64_t unix_sec = 0;

    memcpy(&sec, Data, sizeof(int32_t));
    memcpy(&usec, Data + sizeof(int32_t), sizeof(int32_t));

    if (Size >= sizeof(int32_t) * 2 + sizeof(int64_t)) {
        memcpy(&unix_sec, Data + sizeof(int32_t) * 2, sizeof(int64_t));
    }

    // Create a new plist date node
    plist_t node = plist_new_date(sec, usec);
    if (!node) {
        return 0;
    }

    // Set date value using deprecated function
    plist_set_date_val(node, sec, usec);

    // Set date value using recommended function
    plist_set_unix_date_val(node, unix_sec);

    // Retrieve date value
    int32_t ret_sec = 0;
    int32_t ret_usec = 0;
    plist_get_date_val(node, &ret_sec, &ret_usec);

    // Compare using deprecated function
    plist_date_val_compare(node, sec, usec);

    // Compare using recommended function
    plist_unix_date_val_compare(node, unix_sec);

    // Free the plist node
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    