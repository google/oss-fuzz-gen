// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_float4 at floats_ctrls.c:174:14 in floats_ctrls.h
// cbor_new_float2 at floats_ctrls.c:113:14 in floats_ctrls.h
// cbor_float_get_float2 at floats_ctrls.c:28:7 in floats_ctrls.h
// cbor_build_float2 at floats_ctrls.c:167:14 in floats_ctrls.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "cbor.h"
#include "cbor.h"
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(float)) {
        return 0;
    }

    // Extract a float value from the input data
    float value;
    std::memcpy(&value, Data, sizeof(float));

    // Test cbor_build_float4
    cbor_item_t* item_float4 = cbor_build_float4(value);
    if (item_float4 != nullptr) {
        // Test cbor_isa_float_ctrl
        bool is_float_ctrl = cbor_isa_float_ctrl(item_float4);
        std::cout << "cbor_isa_float_ctrl: " << is_float_ctrl << std::endl;

        // Test cbor_is_float
        bool is_float = cbor_is_float(item_float4);
        std::cout << "cbor_is_float: " << is_float << std::endl;

        // Clean up
        free(item_float4);
    }

    // Test cbor_new_float2
    cbor_item_t* item_new_float2 = cbor_new_float2();
    if (item_new_float2 != nullptr) {
        // Test cbor_float_get_float2
        if (item_new_float2->type == CBOR_TYPE_FLOAT_CTRL) {
            float retrieved_value = cbor_float_get_float2(item_new_float2);
            std::cout << "cbor_float_get_float2: " << retrieved_value << std::endl;
        }

        // Clean up
        free(item_new_float2);
    }

    // Test cbor_build_float2
    cbor_item_t* item_float2 = cbor_build_float2(value);
    if (item_float2 != nullptr) {
        // Test cbor_isa_float_ctrl
        bool is_float_ctrl = cbor_isa_float_ctrl(item_float2);
        std::cout << "cbor_isa_float_ctrl: " << is_float_ctrl << std::endl;

        // Test cbor_is_float
        bool is_float = cbor_is_float(item_float2);
        std::cout << "cbor_is_float: " << is_float << std::endl;

        // Clean up
        free(item_float2);
    }

    return 0;
}