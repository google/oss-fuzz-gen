// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_float4 at floats_ctrls.c:174:14 in floats_ctrls.h
// cbor_float_get_float4 at floats_ctrls.c:34:7 in floats_ctrls.h
// cbor_set_float4 at floats_ctrls.c:76:6 in floats_ctrls.h
// cbor_build_float2 at floats_ctrls.c:167:14 in floats_ctrls.h
// cbor_float_get_float2 at floats_ctrls.c:28:7 in floats_ctrls.h
// cbor_set_float2 at floats_ctrls.c:70:6 in floats_ctrls.h
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
#include "memory.h" // Assuming this header provides cbor_decref
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(float)) {
        return 0; // Not enough data to form a float
    }

    // Extract a float value from the input data
    float value;
    std::memcpy(&value, Data, sizeof(float));

    // Test cbor_build_float4
    cbor_item_t *item_float4 = cbor_build_float4(value);
    if (item_float4 != NULL) {
        // Test cbor_float_get_float4
        float retrieved_float4 = cbor_float_get_float4(item_float4);

        // Test cbor_set_float4
        cbor_set_float4(item_float4, value);

        // Clean up
        cbor_decref(&item_float4);
    }

    // Test cbor_build_float2
    cbor_item_t *item_float2 = cbor_build_float2(value);
    if (item_float2 != NULL) {
        // Test cbor_float_get_float2
        float retrieved_float2 = cbor_float_get_float2(item_float2);

        // Test cbor_set_float2
        cbor_set_float2(item_float2, value);

        // Clean up
        cbor_decref(&item_float2);
    }

    return 0;
}