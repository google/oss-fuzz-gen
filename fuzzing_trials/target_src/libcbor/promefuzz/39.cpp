// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_mark_uint at ints.c:82:6 in ints.h
// cbor_get_uint8 at ints.c:15:9 in ints.h
// cbor_set_uint8 at ints.c:58:6 in ints.h
// cbor_get_uint8 at ints.c:15:9 in ints.h
// cbor_mark_uint at ints.c:82:6 in ints.h
// cbor_get_uint64 at ints.c:33:10 in ints.h
// cbor_build_uint8 at ints.c:132:14 in ints.h
// cbor_get_uint8 at ints.c:15:9 in ints.h
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

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a cbor_item_t structure
    cbor_item_t item;
    memset(&item, 0, sizeof(cbor_item_t));

    // Randomly decide on the type of CBOR item
    uint8_t type_decision = Data[0] % 3;
    Data++;
    Size--;

    if (type_decision == 0) {
        // Handle 8-bit integer
        if (Size < 1) return 0;
        uint8_t value = Data[0];
        
        item.metadata.int_metadata.width = CBOR_INT_8;
        item.data = static_cast<unsigned char*>(malloc(sizeof(uint8_t)));
        if (!item.data) return 0;
        memcpy(item.data, &value, sizeof(uint8_t));

        cbor_mark_uint(&item);
        uint8_t extracted_value = cbor_get_uint8(&item);
        assert(extracted_value == value);

        // Ensure the incremented value does not wrap around
        if (value < UINT8_MAX) {
            cbor_set_uint8(&item, value + 1);
            extracted_value = cbor_get_uint8(&item);
            assert(extracted_value == value + 1);
        }

        free(item.data);
    } else if (type_decision == 1) {
        // Handle 64-bit integer
        if (Size < 8) return 0;
        uint64_t value;
        memcpy(&value, Data, sizeof(uint64_t));

        item.metadata.int_metadata.width = CBOR_INT_64;
        item.data = static_cast<unsigned char*>(malloc(sizeof(uint64_t)));
        if (!item.data) return 0;
        memcpy(item.data, &value, sizeof(uint64_t));

        cbor_mark_uint(&item);
        uint64_t extracted_value = cbor_get_uint64(&item);
        assert(extracted_value == value);

        free(item.data);
    } else {
        // Build a new uint8 CBOR item
        if (Size < 1) return 0;
        uint8_t value = Data[0];
        
        cbor_item_t* new_item = cbor_build_uint8(value);
        if (new_item) {
            uint8_t extracted_value = cbor_get_uint8(new_item);
            assert(extracted_value == value);

            // Only free the new_item as its data is managed internally
            free(new_item);
        }
    }

    return 0;
}