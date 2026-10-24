// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_get_bool at floats_ctrls.c:65:6 in floats_ctrls.h
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
extern "C" {
#include "cbor.h"
#include "cbor.h"
}

#include <cstddef>
#include <cstdint>
#include <cstring>

static cbor_item_t* create_dummy_cbor_item() {
    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    item->refcount = 1;
    item->type = CBOR_TYPE_FLOAT_CTRL;
    item->data = (unsigned char*)malloc(1);
    return item;
}

static void delete_dummy_cbor_item(cbor_item_t* item) {
    if (item) {
        free(item->data);
        free(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy CBOR item
    cbor_item_t* item = create_dummy_cbor_item();
    if (!item) return 0;

    // Test cbor_is_bool
    bool is_bool = cbor_is_bool(item);

    // Test cbor_get_bool, only if it's a boolean
    if (is_bool) {
        try {
            bool value = cbor_get_bool(item);
        } catch (...) {
            // Handle any exceptions
        }
    }

    // Test cbor_build_bool
    bool bool_value = Data[0] % 2 == 0;
    cbor_item_t* bool_item = cbor_build_bool(bool_value);
    if (bool_item) {
        // Test cbor_set_bool
        cbor_set_bool(bool_item, !bool_value);
        cbor_decref(&bool_item);
    }

    // Test cbor_is_undef
    bool is_undef = cbor_is_undef(item);

    // Test cbor_float_ctrl_is_ctrl
    bool is_ctrl = cbor_float_ctrl_is_ctrl(item);

    // Clean up
    delete_dummy_cbor_item(item);

    return 0;
}