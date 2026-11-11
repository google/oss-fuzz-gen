// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_date at plist.c:673:9 in plist.h
// plist_set_date_val at plist.c:2056:6 in plist.h
// plist_get_unix_date_val at plist.c:1878:6 in plist.h
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
#include <cstdlib>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2) {
        return 0;
    }

    int32_t sec = *reinterpret_cast<const int32_t*>(Data);
    int32_t usec = *reinterpret_cast<const int32_t*>(Data + sizeof(int32_t));

    plist_t date_node = plist_new_date(sec, usec);
    if (!date_node) {
        return 0;
    }

    // Fuzz plist_set_date_val
    plist_set_date_val(date_node, sec, usec);

    // Fuzz plist_get_unix_date_val
    int64_t unix_sec;
    plist_get_unix_date_val(date_node, &unix_sec);

    // Fuzz plist_get_date_val
    int32_t get_sec, get_usec;
    plist_get_date_val(date_node, &get_sec, &get_usec);

    // Fuzz plist_date_val_compare
    int cmp_result = plist_date_val_compare(date_node, sec, usec);

    // Fuzz plist_unix_date_val_compare
    cmp_result = plist_unix_date_val_compare(date_node, unix_sec);

    // Clean up
    plist_free(date_node);

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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    