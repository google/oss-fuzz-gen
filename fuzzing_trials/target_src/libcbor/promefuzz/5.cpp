// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_float8 at floats_ctrls.c:137:14 in floats_ctrls.h
// cbor_new_float2 at floats_ctrls.c:113:14 in floats_ctrls.h
// cbor_build_float2 at floats_ctrls.c:167:14 in floats_ctrls.h
// cbor_new_float4 at floats_ctrls.c:125:14 in floats_ctrls.h
// cbor_serialize_float_ctrl at serialization.c:377:8 in serialization.h
// cbor_ctrl_value at floats_ctrls.c:17:9 in floats_ctrls.h
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
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    // Fuzz cbor_new_float8
    cbor_item_t *float8_item = cbor_new_float8();

    // Fuzz cbor_new_float2
    cbor_item_t *float2_item = cbor_new_float2();

    // Fuzz cbor_build_float2 with a float value
    cbor_item_t *built_float2_item = nullptr;
    if (Size >= sizeof(float)) {
        float value;
        memcpy(&value, Data, sizeof(float));
        built_float2_item = cbor_build_float2(value);
    }

    // Fuzz cbor_new_float4
    cbor_item_t *float4_item = cbor_new_float4();

    // Fuzz cbor_serialize_float_ctrl
    if (float8_item != NULL) {
        size_t buffer_size = 256; // Arbitrary buffer size
        uint8_t buffer[buffer_size];
        size_t serialized_length = cbor_serialize_float_ctrl(float8_item, buffer, buffer_size);
        // Use serialized_length if necessary
    }

    // Fuzz cbor_ctrl_value
    if (float8_item != NULL) {
        uint8_t ctrl_value = cbor_ctrl_value(float8_item);
        // Use ctrl_value if necessary
    }

    // Cleanup
    if (float8_item != NULL) {
        free(float8_item);
    }
    if (float2_item != NULL) {
        free(float2_item);
    }
    if (built_float2_item != NULL) {
        free(built_float2_item);
    }
    if (float4_item != NULL) {
        free(float4_item);
    }

    return 0;
}