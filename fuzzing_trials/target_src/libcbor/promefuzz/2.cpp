// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_set_uint64 at ints.c:76:6 in ints.h
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
#include <cassert>
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) return 0;

    // Allocate and copy data to a new cbor_item_t
    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (!item) return 0;
    memcpy(item, Data, sizeof(cbor_item_t));

    // Ensure the item has a valid data pointer
    item->data = (unsigned char*)malloc(Size);
    if (!item->data) {
        free(item);
        return 0;
    }
    memcpy(item->data, Data, Size);

    // Fuzz cbor_is_int
    bool is_int = cbor_is_int(item);

    // Fuzz cbor_set_uint64 if item is an integer
    if (is_int) {
        uint64_t value = 0;
        if (Size >= sizeof(uint64_t)) {
            memcpy(&value, Data, sizeof(uint64_t));
        }
        cbor_set_uint64(item, value);
    }

    // Fuzz cbor_is_null
    bool is_null = cbor_is_null(item);

    // Fuzz cbor_isa_bytestring
    bool is_bytestring = cbor_isa_bytestring(item);

    // Fuzz cbor_isa_map
    bool is_map = cbor_isa_map(item);

    // Fuzz cbor_isa_uint
    bool is_uint = cbor_isa_uint(item);

    // Cleanup
    free(item->data);
    free(item);

    return 0;
}