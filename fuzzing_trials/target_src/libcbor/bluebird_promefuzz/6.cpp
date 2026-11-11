#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
extern "C" {
#include "/src/libcbor/src/cbor/encoding.h"
}

#include "cstdint"
#include "cstdlib"
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    // Fuzz cbor_encode_negint
    if (Size >= sizeof(uint64_t)) {
        uint64_t negint_value;
        std::memcpy(&negint_value, Data, sizeof(uint64_t));
        cbor_encode_negint(negint_value, buffer, buffer_size);
    }

    // Fuzz cbor_encode_undef
    cbor_encode_undef(buffer, buffer_size);

    // Fuzz cbor_encode_negint32
    if (Size >= sizeof(uint32_t)) {
        uint32_t negint32_value;
        std::memcpy(&negint32_value, Data, sizeof(uint32_t));
        cbor_encode_negint32(negint32_value, buffer, buffer_size);
    }

    // Fuzz cbor_encode_ctrl
    uint8_t ctrl_value = Data[0];
    cbor_encode_ctrl(ctrl_value, buffer, buffer_size);

    // Fuzz cbor_encode_tag
    if (Size >= sizeof(uint64_t)) {
        uint64_t tag_value;
        std::memcpy(&tag_value, Data, sizeof(uint64_t));
        cbor_encode_tag(tag_value, buffer, buffer_size);
    }

    // Fuzz cbor_encode_uint8
    uint8_t uint8_value = Data[0];
    cbor_encode_uint8(uint8_value, buffer, buffer_size);

    return 0;
}