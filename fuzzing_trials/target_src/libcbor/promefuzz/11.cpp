// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_encode_negint at encoding.c:59:8 in encoding.h
// cbor_encode_uint at encoding.c:34:8 in encoding.h
// cbor_encode_uint16 at encoding.c:19:8 in encoding.h
// cbor_encode_uint64 at encoding.c:29:8 in encoding.h
// cbor_encode_negint16 at encoding.c:44:8 in encoding.h
// cbor_serialize_uint at serialization.c:190:8 in serialization.h
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

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a buffer for encoding
    unsigned char buffer[1024];
    size_t buffer_size = sizeof(buffer);

    // Fuzz cbor_encode_negint
    {
        uint64_t value = Data[0];
        size_t result = cbor_encode_negint(value, buffer, buffer_size);
        (void)result;
    }

    // Fuzz cbor_encode_uint
    {
        uint64_t value = Data[0];
        size_t result = cbor_encode_uint(value, buffer, buffer_size);
        (void)result;
    }

    // Fuzz cbor_encode_uint16
    if (Size >= 2) {
        uint16_t value = *reinterpret_cast<const uint16_t*>(Data);
        size_t result = cbor_encode_uint16(value, buffer, buffer_size);
        (void)result;
    }

    // Fuzz cbor_encode_uint64
    {
        uint64_t value = Data[0];
        size_t result = cbor_encode_uint64(value, buffer, buffer_size);
        (void)result;
    }

    // Fuzz cbor_encode_negint16
    if (Size >= 2) {
        uint16_t value = *reinterpret_cast<const uint16_t*>(Data);
        size_t result = cbor_encode_negint16(value, buffer, buffer_size);
        (void)result;
    }

    // Fuzz cbor_serialize_uint
    if (Size >= sizeof(cbor_item_t)) {
        cbor_item_t item;
        item.type = CBOR_TYPE_UINT;
        item.data = const_cast<unsigned char*>(Data);
        item.refcount = 0;

        size_t result = cbor_serialize_uint(&item, buffer, buffer_size);
        (void)result;
    }

    return 0;
}