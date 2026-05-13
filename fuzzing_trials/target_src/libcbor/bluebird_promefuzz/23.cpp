#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
extern "C" {
#include "cbor.h"
#include "/src/libcbor/src/cbor/ints.h"
}

#include <cstddef>
#include "cstdint"
#include "cstdlib"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    // Create a new 32-bit integer item
    cbor_item_t* int32_item = cbor_new_int32();
    if (int32_item == NULL) return 0;

    // Set the value for the int32_item using the input data
    uint32_t int32_value = *(reinterpret_cast<const uint32_t*>(Data));
    std::memcpy(int32_item->data, &int32_value, sizeof(uint32_t));

    // Mark the integer as negative
    cbor_mark_negint(int32_item);

    // Get the width of the integer
    cbor_int_width width = cbor_int_get_width(int32_item);

    // Extract the integer value
    uint64_t int_value = cbor_get_int(int32_item);

    // Copy the CBOR item
    cbor_item_t* copied_item = cbor_copy(int32_item);
    if (copied_item) {
        // Clean up the copied item
        cbor_decref(&copied_item);
    }

    // Create a negative integer item from a 64-bit value
    uint64_t negint_value = *(reinterpret_cast<const uint64_t*>(Data));
    cbor_item_t* negint_item = cbor_build_negint64(negint_value);
    if (negint_item) {
        // Clean up the negative integer item
        cbor_decref(&negint_item);
    }

    // Clean up the original int32 item
    cbor_decref(&int32_item);

    return 0;
}