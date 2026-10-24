// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_ctrl at floats_ctrls.c:100:14 in floats_ctrls.h
// cbor_ctrl_value at floats_ctrls.c:17:9 in floats_ctrls.h
// cbor_set_ctrl at floats_ctrls.c:88:6 in floats_ctrls.h
// cbor_float_ctrl_is_ctrl at floats_ctrls.c:23:6 in floats_ctrls.h
// cbor_new_float4 at floats_ctrls.c:125:14 in floats_ctrls.h
// cbor_float_ctrl_is_ctrl at floats_ctrls.c:23:6 in floats_ctrls.h
// cbor_build_ctrl at floats_ctrls.c:188:14 in floats_ctrls.h
// cbor_ctrl_value at floats_ctrls.c:17:9 in floats_ctrls.h
// cbor_float_ctrl_is_ctrl at floats_ctrls.c:23:6 in floats_ctrls.h
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
}

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz cbor_new_ctrl
    cbor_item_t* ctrl_item = cbor_new_ctrl();
    if (ctrl_item) {
        // Fuzz cbor_ctrl_value
        uint8_t ctrl_value = cbor_ctrl_value(ctrl_item);

        // Fuzz cbor_set_ctrl with the first byte of Data
        cbor_set_ctrl(ctrl_item, Data[0]);

        // Check if it is a control value
        bool is_ctrl = cbor_float_ctrl_is_ctrl(ctrl_item);

        // Clean up
        // Assuming there is a function to free cbor_item_t, e.g., cbor_decref
        // cbor_decref(&ctrl_item);
    }

    // Fuzz cbor_new_float4
    cbor_item_t* float_item = cbor_new_float4();
    if (float_item) {
        // Check if it is a control value
        bool is_ctrl = cbor_float_ctrl_is_ctrl(float_item);

        // Clean up
        // Assuming there is a function to free cbor_item_t, e.g., cbor_decref
        // cbor_decref(&float_item);
    }

    // Fuzz cbor_build_ctrl with the first byte of Data
    cbor_item_t* built_ctrl_item = cbor_build_ctrl(Data[0]);
    if (built_ctrl_item) {
        // Fuzz cbor_ctrl_value
        uint8_t built_ctrl_value = cbor_ctrl_value(built_ctrl_item);

        // Check if it is a control value
        bool is_ctrl = cbor_float_ctrl_is_ctrl(built_ctrl_item);

        // Clean up
        // Assuming there is a function to free cbor_item_t, e.g., cbor_decref
        // cbor_decref(&built_ctrl_item);
    }

    return 0;
}