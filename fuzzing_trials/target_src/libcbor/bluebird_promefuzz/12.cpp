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
#include "/src/libcbor/src/cbor/common.h"
#include "/src/libcbor/src/cbor/floats_ctrls.h"
}

#include <cstddef>
#include "cstdint"
#include "cstdio"

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a CBOR boolean item using the first byte of the input data
    bool initial_bool_value = Data[0] % 2 == 0;
    cbor_item_t* bool_item = cbor_build_bool(initial_bool_value);
    if (!bool_item) return 0;

    // Test cbor_is_bool
    bool is_bool = cbor_is_bool(bool_item);

    // Test cbor_get_bool
    if (is_bool) {
        bool retrieved_bool_value = cbor_get_bool(bool_item);
    }

    // Modify the boolean value using the second byte if available
    if (Size > 1) {
        bool new_bool_value = Data[1] % 2 == 0;
        cbor_set_bool(bool_item, new_bool_value);
    }

    // Clean up
    cbor_decref(&bool_item);

    // Create a CBOR control item using the third byte if available
    if (Size > 2) {
        uint8_t ctrl_value = Data[2];
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