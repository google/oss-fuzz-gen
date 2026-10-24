// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_negint32 at ints.c:180:14 in ints.h
// cbor_mark_negint at ints.c:87:6 in ints.h
// cbor_build_negint8 at ints.c:164:14 in ints.h
// cbor_mark_negint at ints.c:87:6 in ints.h
// cbor_build_negint64 at ints.c:188:14 in ints.h
// cbor_mark_negint at ints.c:87:6 in ints.h
// cbor_mark_negint at ints.c:87:6 in ints.h
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

static cbor_item_t* create_random_cbor_item(const uint8_t* Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) return nullptr;
    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (!item) return nullptr;
    memcpy(item, Data, sizeof(cbor_item_t));
    item->data = (unsigned char*)malloc(Size - sizeof(cbor_item_t));
    if (!item->data) {
        free(item);
        return nullptr;
    }
    memcpy(item->data, Data + sizeof(cbor_item_t), Size - sizeof(cbor_item_t));
    return item;
}

static void destroy_cbor_item(cbor_item_t* item) {
    if (item) {
        free(item->data);
        free(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Test cbor_build_negint32
    uint32_t value32 = static_cast<uint32_t>(Data[0]);
    cbor_item_t* negint32 = cbor_build_negint32(value32);
    if (negint32) {
        bool is_int = cbor_is_int(negint32);
        if (is_int) {
            cbor_mark_negint(negint32);
            bool is_negint = cbor_isa_negint(negint32);
        }
        cbor_decref(&negint32);
    }

    // Test cbor_build_negint8
    uint8_t value8 = static_cast<uint8_t>(Data[0]);
    cbor_item_t* negint8 = cbor_build_negint8(value8);
    if (negint8) {
        bool is_int = cbor_is_int(negint8);
        if (is_int) {
            cbor_mark_negint(negint8);
            bool is_negint = cbor_isa_negint(negint8);
        }
        cbor_decref(&negint8);
    }

    // Test cbor_build_negint64
    if (Size >= sizeof(uint64_t)) {
        uint64_t value64;
        memcpy(&value64, Data, sizeof(uint64_t));
        cbor_item_t* negint64 = cbor_build_negint64(value64);
        if (negint64) {
            bool is_int = cbor_is_int(negint64);
            if (is_int) {
                cbor_mark_negint(negint64);
                bool is_negint = cbor_isa_negint(negint64);
            }
            cbor_decref(&negint64);
        }
    }

    // Test creating a random CBOR item and invoking functions
    cbor_item_t* random_item = create_random_cbor_item(Data, Size);
    if (random_item) {
        bool is_int = cbor_is_int(random_item);
        if (is_int) {
            cbor_mark_negint(random_item);
            bool is_negint = cbor_isa_negint(random_item);
        }
        destroy_cbor_item(random_item);
    }

    return 0;
}