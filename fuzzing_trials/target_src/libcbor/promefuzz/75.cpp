// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_float_get_float2 at floats_ctrls.c:28:7 in floats_ctrls.h
// cbor_ctrl_value at floats_ctrls.c:17:9 in floats_ctrls.h
// cbor_float_ctrl_is_ctrl at floats_ctrls.c:23:6 in floats_ctrls.h
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

static cbor_item_t* create_cbor_item(const uint8_t* data, size_t size) {
    cbor_item_t* item = new cbor_item_t();
    item->refcount = 0;
    item->data = new unsigned char[size];
    std::memcpy(item->data, data, size);

    // Randomly assign a type for testing purposes
    item->type = static_cast<cbor_type>(data[0] % 8);
    return item;
}

static void free_cbor_item(cbor_item_t* item) {
    if (item) {
        delete[] item->data;
        delete item;
    }
}

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t* Data, size_t Size) {
    if (Size < 1) return 0;

    cbor_item_t* item = create_cbor_item(Data, Size);

    // Test cbor_is_null
    bool is_null = cbor_is_null(item);

    // Test cbor_isa_float_ctrl
    bool isa_float_ctrl = cbor_isa_float_ctrl(item);

    // Test cbor_is_float
    bool is_float = cbor_is_float(item);

    // Test cbor_float_get_float2
    if (isa_float_ctrl && item->type == CBOR_TYPE_FLOAT_CTRL && Size >= 4) {
        float float2 = cbor_float_get_float2(item);
        (void)float2; // Suppress unused variable warning
    }

    // Test cbor_ctrl_value
    if (isa_float_ctrl && item->type == CBOR_TYPE_FLOAT_CTRL) {
        uint8_t ctrl_value = cbor_ctrl_value(item);
        (void)ctrl_value; // Suppress unused variable warning
    }

    // Test cbor_float_ctrl_is_ctrl
    bool float_ctrl_is_ctrl = cbor_float_ctrl_is_ctrl(item);

    // Cleanup
    free_cbor_item(item);

    return 0;
}