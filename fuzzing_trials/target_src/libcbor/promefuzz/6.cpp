// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_negint32 at ints.c:180:14 in ints.h
// cbor_get_uint32 at ints.c:27:10 in ints.h
// cbor_new_int32 at ints.c:112:14 in ints.h
// cbor_build_uint32 at ints.c:148:14 in ints.h
// cbor_get_uint32 at ints.c:27:10 in ints.h
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
#include <cassert>
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    // Extract a uint32_t value from the input data
    uint32_t value = 0;
    memcpy(&value, Data, sizeof(uint32_t));

    // Test cbor_build_negint32
    cbor_item_t* negint_item = cbor_build_negint32(value);
    if (negint_item) {
        // Test cbor_is_int
        bool is_int = cbor_is_int(negint_item);
        assert(is_int == true);

        // Test cbor_move
        cbor_item_t* moved_negint_item = cbor_move(negint_item);

        // Test cbor_get_uint32 if the item is correctly set to 32-bit width
        if (moved_negint_item && moved_negint_item->metadata.int_metadata.width == CBOR_INT_32) {
            uint32_t extracted_value = cbor_get_uint32(moved_negint_item);
            (void)extracted_value; // Use the extracted value
        }

        // Clean up
        cbor_decref(&moved_negint_item);
    }

    // Test cbor_new_int32
    cbor_item_t* int32_item = cbor_new_int32();
    if (int32_item) {
        // Test cbor_build_uint32
        cbor_item_t* uint32_item = cbor_build_uint32(value);
        if (uint32_item) {
            // Test cbor_is_int
            bool is_uint_int = cbor_is_int(uint32_item);
            assert(is_uint_int == true);

            // Test cbor_move
            cbor_item_t* moved_uint32_item = cbor_move(uint32_item);

            // Test cbor_get_uint32 if the item is correctly set to 32-bit width
            if (moved_uint32_item && moved_uint32_item->metadata.int_metadata.width == CBOR_INT_32) {
                uint32_t extracted_value = cbor_get_uint32(moved_uint32_item);
                (void)extracted_value; // Use the extracted value
            }

            // Clean up
            cbor_decref(&moved_uint32_item);
        }

        // Clean up
        cbor_decref(&int32_item);
    }

    return 0;
}