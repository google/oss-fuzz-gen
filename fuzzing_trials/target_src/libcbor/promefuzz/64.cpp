// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_set_uint64 at ints.c:76:6 in ints.h
// cbor_mark_uint at ints.c:82:6 in ints.h
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
#include <cstdlib>
#include <cstring>
}

static cbor_item_t* create_cbor_item(cbor_type type, size_t data_size) {
    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (item) {
        memset(item, 0, sizeof(cbor_item_t));
        item->type = type;
        item->metadata.int_metadata.width = CBOR_INT_64; // Assuming 64-bit width
        item->data = (unsigned char*)malloc(data_size);
    }
    return item;
}

static void free_cbor_item(cbor_item_t* item) {
    if (item) {
        free(item->data);
        free(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    // Create a CBOR item for testing
    cbor_item_t* item = create_cbor_item(CBOR_TYPE_UINT, sizeof(uint64_t));
    if (!item) return 0;

    // Copy data into the CBOR item
    memcpy(item->data, Data, sizeof(uint64_t));

    // Test cbor_is_int
    bool is_int = cbor_is_int(item);

    // Test cbor_set_uint64
    uint64_t value = *((uint64_t*)Data);
    if (is_int) {
        cbor_set_uint64(item, value);
    }

    // Test cbor_is_null
    bool is_null = cbor_is_null(item);

    // Test cbor_mark_uint
    if (is_int) {
        cbor_mark_uint(item);
    }

    // Test cbor_isa_map
    bool isa_map = cbor_isa_map(item);

    // Test cbor_isa_uint
    bool isa_uint = cbor_isa_uint(item);

    // Clean up
    free_cbor_item(item);

    return 0;
}