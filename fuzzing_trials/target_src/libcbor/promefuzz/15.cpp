// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_encode_undef at encoding.c:126:8 in encoding.h
// cbor_encode_break at encoding.c:208:8 in encoding.h
// cbor_encode_null at encoding.c:122:8 in encoding.h
// cbor_encode_indef_string_start at encoding.c:88:8 in encoding.h
// cbor_encode_indef_bytestring_start at encoding.c:78:8 in encoding.h
// cbor_encode_indef_array_start at encoding.c:98:8 in encoding.h
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
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Use the input data as a buffer
    unsigned char* buffer = new unsigned char[Size];

    // Fuzz cbor_encode_undef
    cbor_encode_undef(buffer, Size);

    // Fuzz cbor_encode_break
    cbor_encode_break(buffer, Size);

    // Fuzz cbor_encode_null
    cbor_encode_null(buffer, Size);

    // Fuzz cbor_encode_indef_string_start
    cbor_encode_indef_string_start(buffer, Size);

    // Fuzz cbor_encode_indef_bytestring_start
    cbor_encode_indef_bytestring_start(buffer, Size);

    // Fuzz cbor_encode_indef_array_start
    cbor_encode_indef_array_start(buffer, Size);

    delete[] buffer;
    return 0;
}