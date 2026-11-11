// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_float_get_width at floats_ctrls.c:12:18 in floats_ctrls.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "cbor.h"
#include "cbor.h"

static cbor_item_t* create_random_cbor_item(const uint8_t* data, size_t size) {
    if (size < sizeof(cbor_item_t)) {
        return nullptr;
    }

    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (!item) {
        return nullptr;
    }

    memcpy(item, data, sizeof(cbor_item_t));
    item->data = nullptr;

    if (size > sizeof(cbor_item_t)) {
        item->data = (unsigned char*)malloc(size - sizeof(cbor_item_t));
        if (item->data) {
            memcpy(item->data, data + sizeof(cbor_item_t), size - sizeof(cbor_item_t));
        }
    }

    return item;
}

static void destroy_cbor_item(cbor_item_t* item) {
    if (item) {
        free(item->data);
        free(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t* Data, size_t Size) {
    cbor_item_t* item = create_random_cbor_item(Data, Size);
    if (!item) {
        return 0;
    }

    // Test cbor_float_get_width
    if (item->type == CBOR_TYPE_FLOAT_CTRL) {
        cbor_float_get_width(item);
    }

    // Test cbor_is_null
    cbor_is_null(item);

    // Test cbor_isa_float_ctrl
    cbor_isa_float_ctrl(item);

    // Test cbor_is_float
    cbor_is_float(item);

    // Test cbor_ctrl_value
    if (item->type == CBOR_TYPE_FLOAT_CTRL) {
        cbor_ctrl_value(item);
    }

    // Test cbor_float_ctrl_is_ctrl
    if (item->type == CBOR_TYPE_FLOAT_CTRL) {
        cbor_float_ctrl_is_ctrl(item);
    }

    destroy_cbor_item(item);
    return 0;
}