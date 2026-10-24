// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_bool at floats_ctrls.c:163:14 in floats_ctrls.h
// cbor_get_bool at floats_ctrls.c:65:6 in floats_ctrls.h
// cbor_set_bool at floats_ctrls.c:94:6 in floats_ctrls.h
// cbor_build_ctrl at floats_ctrls.c:188:14 in floats_ctrls.h
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
#include "cbor.h"
#include "cbor.h"
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Use the first byte to determine a boolean value
    bool bool_value = Data[0] % 2 == 0;

    // Test cbor_build_bool
    cbor_item_t* bool_item = cbor_build_bool(bool_value);
    if (bool_item) {
        // Test cbor_is_bool
        bool is_bool = cbor_is_bool(bool_item);
        
        // Test cbor_get_bool
        if (is_bool) {
            bool retrieved_bool = cbor_get_bool(bool_item);
        }

        // Test cbor_set_bool
        cbor_set_bool(bool_item, !bool_value);

        // Clean up
        cbor_decref(&bool_item);
    }

    // Use the second byte to determine a control value if available
    if (Size > 1) {
        uint8_t ctrl_value = Data[1];

        // Test cbor_build_ctrl
        cbor_item_t* ctrl_item = cbor_build_ctrl(ctrl_value);
        if (ctrl_item) {
            // Test cbor_float_ctrl_is_ctrl
            bool is_ctrl = cbor_float_ctrl_is_ctrl(ctrl_item);

            // Clean up
            cbor_decref(&ctrl_item);
        }
    }

    return 0;
}