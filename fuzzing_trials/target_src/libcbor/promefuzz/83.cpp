// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_get_bool at floats_ctrls.c:65:6 in floats_ctrls.h
// cbor_set_bool at floats_ctrls.c:94:6 in floats_ctrls.h
// cbor_build_bool at floats_ctrls.c:163:14 in floats_ctrls.h
// cbor_set_bool at floats_ctrls.c:94:6 in floats_ctrls.h
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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy cbor_item_t
    cbor_item_t item;
    item.refcount = 1;
    item.type = static_cast<cbor_type>(Data[0] % 8); // Randomly choose a type
    item.data = nullptr;

    // Fuzz cbor_is_bool
    bool is_bool = cbor_is_bool(&item);

    // If it's a boolean, try cbor_get_bool and cbor_set_bool
    if (is_bool) {
        bool value = cbor_get_bool(&item);
        cbor_set_bool(&item, !value); // Toggle the boolean value
    }

    // Fuzz cbor_build_bool
    cbor_item_t* bool_item = cbor_build_bool(Data[0] % 2 == 0);
    if (bool_item != nullptr) {
        // Fuzz cbor_set_bool on newly created item
        cbor_set_bool(bool_item, Data[0] % 2 == 1);

        // Clean up
        free(bool_item);
    }

    // Fuzz cbor_is_undef
    bool is_undef = cbor_is_undef(&item);

    // Fuzz cbor_float_ctrl_is_ctrl
    bool is_ctrl = cbor_float_ctrl_is_ctrl(&item);

    return 0;
}