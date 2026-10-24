// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_uid at plist.c:627:9 in plist.h
// plist_get_uid_val at plist.c:1812:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_uint at plist.c:601:9 in plist.h
// plist_get_uint_val at plist.c:1795:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_uint at plist.c:601:9 in plist.h
// plist_to_openstep_with_options at oplist.c:557:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_array at plist.c:538:9 in plist.h
// plist_new_uint at plist.c:601:9 in plist.h
// plist_array_append_item at plist.c:1079:6 in plist.h
// plist_array_next_item at plist.c:1168:6 in plist.h
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

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));

    // Test plist_new_uid and plist_get_uid_val
    plist_t uid_node = plist_new_uid(value);
    if (uid_node) {
        uint64_t retrieved_uid_value;
        plist_get_uid_val(uid_node, &retrieved_uid_value);
        plist_free(uid_node);
    }

    // Test plist_new_uint and plist_get_uint_val
    plist_t uint_node = plist_new_uint(value);
    if (uint_node) {
        uint64_t retrieved_uint_value;
        plist_get_uint_val(uint_node, &retrieved_uint_value);
        plist_free(uint_node);
    }

    // Test plist_to_openstep_with_options
    plist_t test_node = plist_new_uint(value); // Create a simple node for testing
    if (test_node) {
        char *openstep_format = nullptr;
        uint32_t length = 0;
        plist_write_options_t options = static_cast<plist_write_options_t>(PLIST_OPT_COMPACT | PLIST_OPT_COERCE);
        plist_err_t result = plist_to_openstep_with_options(test_node, &openstep_format, &length, options);
        if (result == PLIST_ERR_SUCCESS && openstep_format) {
            plist_mem_free(openstep_format);
        }
        plist_free(test_node);
    }

    // Test plist_array_next_item
    plist_t array_node = plist_new_array();
    if (array_node) {
        plist_array_append_item(array_node, plist_new_uint(value));
        plist_array_iter iter = nullptr;
        plist_t item = nullptr;
        plist_array_next_item(array_node, iter, &item);
        plist_free(array_node);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    