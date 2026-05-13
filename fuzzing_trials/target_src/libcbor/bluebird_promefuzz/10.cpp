#include <iostream>
#include "cstdlib"
#include <cstring>
#include "cstdint"
#include "/src/libcbor/src/cbor/common.h"
#include "/src/libcbor/src/cbor/arrays.h"

static cbor_item_t* create_cbor_array(size_t size, bool indefinite) {
    cbor_item_t* array = indefinite ? cbor_new_indefinite_array() : cbor_new_definite_array(size);
    return array;
}

static cbor_item_t* create_cbor_item(cbor_type type) {
    cbor_item_t* item = cbor_new_definite_array(1); // Placeholder for actual item creation
    if (!item) return nullptr;
    item->type = type;
    item->refcount = 1;
    return item;
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    bool indefinite = Data[0] % 2 == 0;
    size_t array_size = Data[1];

    cbor_item_t* array = create_cbor_array(array_size, indefinite);
    if (!array) return 0;

    cbor_item_t* new_item = create_cbor_item(CBOR_TYPE_UINT);
    if (!new_item) {
        cbor_decref(&array);
        return 0;
    }

    if (cbor_isa_array(array)) {
        cbor_array_set(array, 0, new_item);
        cbor_array_is_indefinite(array);
        cbor_array_is_definite(array);
        cbor_array_push(array, new_item);
        cbor_array_replace(array, 0, new_item);
    }

    cbor_decref(&new_item);
    cbor_decref(&array);

    return 0;
}