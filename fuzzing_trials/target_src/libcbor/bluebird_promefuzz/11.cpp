#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
#include "cstdint"
#include <cstring>
#include "/src/libcbor/src/cbor/encoding.h"

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    // Fuzz cbor_encode_break
    cbor_encode_break(buffer, buffer_size);

    // Fuzz cbor_encode_uint64
    if (Size >= sizeof(uint64_t)) {
        uint64_t value64;
        memcpy(&value64, Data, sizeof(uint64_t));
        cbor_encode_uint64(value64, buffer, buffer_size);
    }

    // Fuzz cbor_encode_uint32
    if (Size >= sizeof(uint32_t)) {
        uint32_t value32;
        memcpy(&value32, Data, sizeof(uint32_t));
        cbor_encode_uint32(value32, buffer, buffer_size);
    }

    // Fuzz cbor_encode_bool
    bool bool_value = Data[0] % 2 == 0;
    cbor_encode_bool(bool_value, buffer, buffer_size);

    // Fuzz cbor_encode_uint8
    uint8_t value8 = Data[0];
    cbor_encode_uint8(value8, buffer, buffer_size);

    // Fuzz cbor_encode_map_start
    if (Size >= sizeof(size_t)) {
        size_t map_size;
        memcpy(&map_size, Data, sizeof(size_t));
        cbor_encode_map_start(map_size, buffer, buffer_size);
    }

    return 0;
}