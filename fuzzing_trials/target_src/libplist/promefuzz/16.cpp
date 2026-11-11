// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_unix_date at plist.c:686:9 in plist.h
// plist_set_unix_date_val at plist.c:2062:6 in plist.h
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
#include <iostream>
#include "plist.h"

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) {
        return 0;
    }

    int64_t timestamp = *reinterpret_cast<const int64_t*>(Data);

    // Fuzz plist_new_unix_date
    plist_t date_node = plist_new_unix_date(timestamp);
    if (date_node == nullptr) {
        return 0;
    }

    // Fuzz plist_set_unix_date_val
    plist_set_unix_date_val(date_node, timestamp);

    // Fuzz plist_get_unix_date_val
    int64_t extracted_timestamp = 0;
    plist_get_unix_date_val(date_node, &extracted_timestamp);

    // Fuzz plist_get_date_val (deprecated)
    int32_t sec = 0, usec = 0;
    plist_get_date_val(date_node, &sec, &usec);

    // Fuzz plist_date_val_compare (deprecated)
    int compare_result = plist_date_val_compare(date_node, sec, usec);

    // Fuzz plist_unix_date_val_compare
    int unix_compare_result = plist_unix_date_val_compare(date_node, timestamp);

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    