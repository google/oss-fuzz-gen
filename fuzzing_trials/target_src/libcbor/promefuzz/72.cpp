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
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static cbor_item_t* create_cbor_item(cbor_type type, size_t size) {
    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (item) {
        item->type = type;
        item->data = (unsigned char*)malloc(size);
        if (!item->data) {
            free(item);
            return nullptr;
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

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));

    cbor_item_t* int_item = create_cbor_item(CBOR_TYPE_UINT, sizeof(uint64_t));
    if (!int_item) return 0;

    cbor_set_uint64(int_item, value);

    bool is_int = cbor_is_int(int_item);
    bool is_null = cbor_is_null(int_item);
    bool isa_map = cbor_isa_map(int_item);
    bool isa_uint = cbor_isa_uint(int_item);

    if (is_int) {
        cbor_mark_uint(int_item);
    }

    destroy_cbor_item(int_item);

    return 0;
}