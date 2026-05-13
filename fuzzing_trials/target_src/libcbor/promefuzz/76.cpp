// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_int64 at ints.c:122:14 in ints.h
// cbor_build_negint32 at ints.c:180:14 in ints.h
// cbor_new_int32 at ints.c:112:14 in ints.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "cbor.h"
#include "cbor.h"
}

#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for uint32_t

    // Test cbor_new_int64
    cbor_item_t *int64_item = cbor_new_int64();
    if (int64_item) {
        // Test cbor_is_int
        bool is_int64 = cbor_is_int(int64_item);
        
        // Test cbor_incref
        cbor_item_t *incref_item = cbor_incref(int64_item);
        
        // Test cbor_move
        cbor_item_t *moved_item = cbor_move(incref_item);

        // Cleanup
        cbor_decref(&moved_item);
    }

    // Test cbor_build_negint32
    uint32_t value = *(reinterpret_cast<const uint32_t*>(Data));
    cbor_item_t *negint32_item = cbor_build_negint32(value);
    if (negint32_item) {
        // Test cbor_is_int
        bool is_negint32 = cbor_is_int(negint32_item);

        // Test cbor_incref
        cbor_item_t *incref_negint32 = cbor_incref(negint32_item);

        // Test cbor_move
        cbor_item_t *moved_negint32 = cbor_move(incref_negint32);

        // Cleanup
        cbor_decref(&moved_negint32);
    }

    // Test cbor_new_int32
    cbor_item_t *int32_item = cbor_new_int32();
    if (int32_item) {
        // Test cbor_is_int
        bool is_int32 = cbor_is_int(int32_item);

        // Test cbor_incref
        cbor_item_t *incref_int32 = cbor_incref(int32_item);

        // Test cbor_move
        cbor_item_t *moved_int32 = cbor_move(incref_int32);

        // Cleanup
        cbor_decref(&moved_int32);
    }

    return 0;
}