#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "plist/plist.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) return 0;

    int64_t unix_timestamp;
    memcpy(&unix_timestamp, Data, sizeof(int64_t));

    // Test plist_new_null
    plist_t null_node = plist_new_null();
    if (null_node) {
        plist_free(null_node);
    }

    // Test plist_new_unix_date
    plist_t date_node = plist_new_unix_date(unix_timestamp);
    if (date_node) {
        // Test plist_set_unix_date_val
        plist_set_unix_date_val(date_node, unix_timestamp);

        // Test plist_date_val_compare
        plist_date_val_compare(date_node, static_cast<int32_t>(unix_timestamp), 0);

        // Test plist_unix_date_val_compare
        plist_unix_date_val_compare(date_node, unix_timestamp);

        // Test plist_to_openstep_with_options
        char *openstep_output = nullptr;
        uint32_t length = 0;
        plist_err_t err = plist_to_openstep_with_options(date_node, &openstep_output, &length, PLIST_OPT_COERCE);
        if (err == PLIST_ERR_SUCCESS && openstep_output) {
            free(openstep_output);
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
