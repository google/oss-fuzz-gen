// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_set_uint64 at ints.c:76:6 in ints.h
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
#include "cbor.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static cbor_item_t* create_cbor_item(cbor_type type) {
    cbor_item_t* item = cbor_new_definite_bytestring();
    if (!item) return nullptr;
    item->type = type;
    item->data = static_cast<unsigned char*>(malloc(sizeof(uint64_t)));  // Allocate memory for data
    if (!item->data) {
        cbor_decref(&item);
        return nullptr;
    }
    return item;
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));

    // Create a CBOR item for testing
    cbor_item_t* item = create_cbor_item(CBOR_TYPE_UINT);
    if (!item) return 0;

    // Test cbor_is_int
    bool is_int = cbor_is_int(item);

    // Test cbor_set_uint64 only if the item is a valid integer
    if (is_int) {
        cbor_set_uint64(item, value);
    }

    // Test cbor_is_null
    bool is_null = cbor_is_null(item);

    // Test cbor_isa_bytestring
    bool is_bytestring = cbor_isa_bytestring(item);

    // Test cbor_isa_map
    bool is_map = cbor_isa_map(item);

    // Test cbor_isa_uint
    bool is_uint = cbor_isa_uint(item);

    // Clean up
    free(item->data);  // Free the allocated memory
    cbor_decref(&item);

    return 0;
}