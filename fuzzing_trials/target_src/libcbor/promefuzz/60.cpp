// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_float_get_width at floats_ctrls.c:12:18 in floats_ctrls.h
// cbor_float_get_width at floats_ctrls.c:12:18 in floats_ctrls.h
// cbor_float_get_float2 at floats_ctrls.c:28:7 in floats_ctrls.h
// cbor_float_ctrl_is_ctrl at floats_ctrls.c:23:6 in floats_ctrls.h
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
#include <cstring>
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) {
        return 0;
    }

    // Create a CBOR item from the input data
    cbor_item_t item;
    std::memcpy(&item, Data, sizeof(cbor_item_t));

    // Ensure the item type is within valid range
    if (item.type > CBOR_TYPE_FLOAT_CTRL) {
        return 0;
    }

    // Allocate memory for the data pointer
    unsigned char fake_data[4] = {0}; // Assuming at least 4 bytes for a float
    item.data = fake_data;

    // Fuzz cbor_float_get_width
    if (item.type == CBOR_TYPE_FLOAT_CTRL) {
        cbor_float_width width = cbor_float_get_width(&item);
    }

    // Fuzz cbor_is_null
    bool is_null = cbor_is_null(&item);

    // Fuzz cbor_isa_float_ctrl
    bool isa_float_ctrl = cbor_isa_float_ctrl(&item);

    // Fuzz cbor_is_float
    bool is_float = cbor_is_float(&item);

    // Fuzz cbor_float_get_float2
    if (item.type == CBOR_TYPE_FLOAT_CTRL && cbor_float_get_width(&item) == 16) {
        float half_precision = cbor_float_get_float2(&item);
    }

    // Fuzz cbor_float_ctrl_is_ctrl
    if (item.type == CBOR_TYPE_FLOAT_CTRL) {
        bool is_ctrl = cbor_float_ctrl_is_ctrl(&item);
    }

    return 0;
}