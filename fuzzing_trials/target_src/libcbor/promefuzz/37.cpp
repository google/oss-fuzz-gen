// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_encode_indef_string_start at encoding.c:88:8 in encoding.h
// cbor_encode_string_start at encoding.c:83:8 in encoding.h
// cbor_encode_uint32 at encoding.c:24:8 in encoding.h
// cbor_encode_bytestring_start at encoding.c:64:8 in encoding.h
// cbor_encode_uint8 at encoding.c:14:8 in encoding.h
// cbor_encode_map_start at encoding.c:103:8 in encoding.h
#include <iostream>
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

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a buffer for encoding operations
    unsigned char buffer[1024]; // Arbitrary buffer size for testing

    // Fuzz cbor_encode_indef_string_start
    if (Size > 0) {
        cbor_encode_indef_string_start(buffer, sizeof(buffer));
    }

    // Fuzz cbor_encode_string_start
    if (Size > 0) {
        size_t string_length = Data[0] % 256;  // Limit length for testing
        cbor_encode_string_start(string_length, buffer, sizeof(buffer));
    }

    // Fuzz cbor_encode_uint32
    if (Size >= sizeof(uint32_t)) {
        uint32_t uint32_value;
        memcpy(&uint32_value, Data, sizeof(uint32_t));
        cbor_encode_uint32(uint32_value, buffer, sizeof(buffer));
    }

    // Fuzz cbor_encode_bytestring_start
    if (Size > 0) {
        size_t bytestring_length = Data[0] % 256;  // Limit length for testing
        cbor_encode_bytestring_start(bytestring_length, buffer, sizeof(buffer));
    }

    // Fuzz cbor_encode_uint8
    if (Size > 0) {
        uint8_t uint8_value = Data[0];
        cbor_encode_uint8(uint8_value, buffer, sizeof(buffer));
    }

    // Fuzz cbor_encode_map_start
    if (Size > 0) {
        size_t map_length = Data[0] % 256;  // Limit length for testing
        cbor_encode_map_start(map_length, buffer, sizeof(buffer));
    }

    return 0;
}