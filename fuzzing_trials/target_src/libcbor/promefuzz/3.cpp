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
#include <cstdlib>

static cbor_item_t* create_cbor_item(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) {
        return nullptr;
    }

    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (!item) {
        return nullptr;
    }

    // Initialize the cbor_item_t structure
    item->refcount = 0;
    item->type = static_cast<cbor_type>(Data[0] % 8);  // Ensure type is valid
    item->data = nullptr;

    // Depending on the type, additional initialization may be needed
    // This is a basic initialization for fuzzing purposes
    return item;
}

static void destroy_cbor_item(cbor_item_t* item) {
    if (item) {
        free(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t* Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    cbor_item_t* item = create_cbor_item(Data, Size);
    if (!item) {
        return 0;
    }

    // Fuzz the target API functions
    bool is_int = cbor_is_int(item);
    bool is_bool = cbor_is_bool(item);
    bool is_null = cbor_is_null(item);
    bool isa_tag = cbor_isa_tag(item);
    bool is_undef = cbor_is_undef(item);
    bool float_ctrl_is_ctrl = cbor_float_ctrl_is_ctrl(item);

    // Use the results to avoid any compiler optimizations
    volatile bool results[] = {is_int, is_bool, is_null, isa_tag, is_undef, float_ctrl_is_ctrl};
    (void)results;

    destroy_cbor_item(item);
    return 0;
}