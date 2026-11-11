#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
#include "cstdint"
#include <cstddef>
#include "cstdio"
#include "cstdlib"
#include "/src/libcbor/src/cbor/ints.h"  // Include the necessary header for libcbor functions

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz cbor_build_negint8
    uint8_t value8 = Data[0];
    cbor_item_t* item8 = cbor_build_negint8(value8);
    if (item8 != nullptr) {
        cbor_mark_negint(item8);
        // Simulate some usage of the item
        free(item8);
    }

    // Fuzz cbor_build_negint16
    if (Size < 2) return 0;
    uint16_t value16 = (Data[0] << 8) | Data[1];
    cbor_item_t* item16 = cbor_build_negint16(value16);
    if (item16 != nullptr) {
        cbor_mark_negint(item16);
        // Simulate some usage of the item
        free(item16);
    }

    // Fuzz cbor_build_negint32
    if (Size < 4) return 0;
    uint32_t value32 = (Data[0] << 24) | (Data[1] << 16) | (Data[2] << 8) | Data[3];
    cbor_item_t* item32 = cbor_build_negint32(value32);
    if (item32 != nullptr) {
        cbor_mark_negint(item32);
        // Simulate some usage of the item
        free(item32);
    }

    // Fuzz cbor_build_negint64
    if (Size < 8) return 0;
    uint64_t value64 = ((uint64_t)Data[0] << 56) | ((uint64_t)Data[1] << 48) |
                       ((uint64_t)Data[2] << 40) | ((uint64_t)Data[3] << 32) |
                       ((uint64_t)Data[4] << 24) | ((uint64_t)Data[5] << 16) |
                       ((uint64_t)Data[6] << 8) | Data[7];
    cbor_item_t* item64 = cbor_build_negint64(value64);
    if (item64 != nullptr) {
        cbor_mark_negint(item64);
        // Simulate some usage of the item
        free(item64);
    }

    // Fuzz cbor_new_int32
    cbor_item_t* new_int32 = cbor_new_int32();
    if (new_int32 != nullptr) {
        cbor_mark_negint(new_int32);
        // Simulate some usage of the item
        free(new_int32);
    }

    return 0;
}