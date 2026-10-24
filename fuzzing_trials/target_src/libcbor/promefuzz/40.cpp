// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_float_get_width at floats_ctrls.c:12:18 in floats_ctrls.h
// cbor_float_get_float2 at floats_ctrls.c:28:7 in floats_ctrls.h
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

static cbor_item_t* create_cbor_item(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) {
        return nullptr;
    }

    cbor_item_t* item = new cbor_item_t();
    std::memcpy(item, Data, sizeof(cbor_item_t));

    // Ensure the data pointer is valid if there's additional data
    if (Size > sizeof(cbor_item_t)) {
        item->data = new unsigned char[Size - sizeof(cbor_item_t)];
        std::memcpy(item->data, Data + sizeof(cbor_item_t), Size - sizeof(cbor_item_t));
    } else {
        item->data = nullptr;
    }

    return item;
}

static void cleanup_cbor_item(cbor_item_t* item) {
    if (item) {
        delete[] item->data;
        delete item;
    }
}

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t* Data, size_t Size) {
    cbor_item_t* item = create_cbor_item(Data, Size);
    if (!item) {
        return 0;
    }

    // Fuzz cbor_float_get_width
    if (item->type == CBOR_TYPE_FLOAT_CTRL) {
        cbor_float_get_width(item);
    }

    // Fuzz cbor_is_null
    cbor_is_null(item);

    // Fuzz cbor_isa_float_ctrl
    cbor_isa_float_ctrl(item);

    // Fuzz cbor_is_float
    cbor_is_float(item);

    // Fuzz cbor_float_get_float2
    if (item->type == CBOR_TYPE_FLOAT_CTRL && item->metadata.float_ctrl_metadata.width == 16 && item->data != nullptr && Size >= sizeof(cbor_item_t) + sizeof(float)) {
        cbor_float_get_float2(item);
    }

    // Fuzz cbor_float_ctrl_is_ctrl
    if (item->type == CBOR_TYPE_FLOAT_CTRL) {
        cbor_float_ctrl_is_ctrl(item);
    }

    cleanup_cbor_item(item);
    return 0;
}