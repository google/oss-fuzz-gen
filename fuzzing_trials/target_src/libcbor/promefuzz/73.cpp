// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
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

static cbor_item_t* create_cbor_item_from_data(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) {
        return nullptr;
    }
    
    cbor_item_t* item = new cbor_item_t;
    std::memcpy(item, Data, sizeof(cbor_item_t));

    if (Size > sizeof(cbor_item_t)) {
        size_t dataSize = Size - sizeof(cbor_item_t);
        item->data = new unsigned char[dataSize];
        std::memcpy(item->data, Data + sizeof(cbor_item_t), dataSize);
    } else {
        item->data = nullptr;
    }

    return item;
}

static void clean_cbor_item(cbor_item_t* item) {
    if (item) {
        delete[] item->data;
        delete item;
    }
}

extern "C" int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size) {
    cbor_item_t* item = create_cbor_item_from_data(Data, Size);
    if (!item) {
        return 0;
    }

    // Test the target functions
    bool is_int = cbor_is_int(item);
    bool is_bool = cbor_is_bool(item);
    bool is_null = cbor_is_null(item);
    bool isa_float_ctrl = cbor_isa_float_ctrl(item);
    bool is_undef = cbor_is_undef(item);
    bool float_ctrl_is_ctrl = cbor_float_ctrl_is_ctrl(item);

    // Use the results of the functions to avoid compiler optimizing them away
    volatile bool results[] = {is_int, is_bool, is_null, isa_float_ctrl, is_undef, float_ctrl_is_ctrl};
    (void)results;

    clean_cbor_item(item);
    return 0;
}