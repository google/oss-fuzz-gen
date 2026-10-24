// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_null at plist.c:699:9 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_unix_date at plist.c:686:9 in plist.h
// plist_set_unix_date_val at plist.c:2062:6 in plist.h
// plist_date_val_compare at plist.c:2182:5 in plist.h
// plist_unix_date_val_compare at plist.c:2206:5 in plist.h
// plist_to_openstep_with_options at oplist.c:557:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
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

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) {
        return 0;
    }

    int64_t timestamp;
    memcpy(&timestamp, Data, sizeof(int64_t));

    // Test plist_new_null
    plist_t null_node = plist_new_null();
    if (null_node) {
        plist_free(null_node);
    }

    // Test plist_new_unix_date
    plist_t date_node = plist_new_unix_date(timestamp);
    if (date_node) {
        // Test plist_set_unix_date_val
        plist_set_unix_date_val(date_node, timestamp);

        // Test plist_date_val_compare
        int cmp_result = plist_date_val_compare(date_node, static_cast<int32_t>(timestamp), 0);

        // Test plist_unix_date_val_compare
        cmp_result = plist_unix_date_val_compare(date_node, timestamp);

        // Prepare for plist_to_openstep_with_options
        char *openstep_output = nullptr;
        uint32_t length = 0;
        plist_err_t err = plist_to_openstep_with_options(date_node, &openstep_output, &length, PLIST_OPT_COERCE);

        if (err == PLIST_ERR_SUCCESS && openstep_output) {
            plist_mem_free(openstep_output);
        }

        plist_free(date_node);
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    