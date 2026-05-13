// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_bytestring at bytestrings.c:61:14 in bytestrings.h
// cbor_bytestring_length at bytestrings.c:12:8 in bytestrings.h
// cbor_serialize_alloc at serialization.c:170:8 in serialization.h
// cbor_new_indefinite_string at strings.c:25:14 in strings.h
// cbor_string_chunk_count at strings.c:89:8 in strings.h
// cbor_build_string at strings.c:44:14 in strings.h
// cbor_string_length at strings.c:122:8 in strings.h
// cbor_new_indefinite_bytestring at bytestrings.c:42:14 in bytestrings.h
// cbor_bytestring_chunk_count at bytestrings.c:86:8 in bytestrings.h
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
#include <cstdlib>
#include <cstring>
#include "cbor.h"
#include "cbor.h"
#include "strings.h"

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Test cbor_build_bytestring
    cbor_item_t* bytestring_item = cbor_build_bytestring(Data, Size);
    if (bytestring_item) {
        // Test cbor_bytestring_length
        size_t length = cbor_bytestring_length(bytestring_item);

        // Test cbor_serialize_alloc
        unsigned char* buffer = nullptr;
        size_t buffer_size = 0;
        cbor_serialize_alloc(bytestring_item, &buffer, &buffer_size);
        if (buffer) {
            free(buffer);
        }

        cbor_decref(&bytestring_item);
    }

    // Test cbor_string_chunk_count with a valid indefinite string
    cbor_item_t* string_item = cbor_new_indefinite_string();
    if (string_item) {
        size_t chunk_count = cbor_string_chunk_count(string_item);
        cbor_decref(&string_item);
    }

    // Test cbor_string_length with a definite string
    std::string str(reinterpret_cast<const char*>(Data), Size);
    cbor_item_t* definite_string_item = cbor_build_string(str.c_str());
    if (definite_string_item) {
        size_t string_length = cbor_string_length(definite_string_item);
        cbor_decref(&definite_string_item);
    }

    // Test cbor_bytestring_chunk_count with a valid indefinite bytestring
    cbor_item_t* indefinite_bytestring_item = cbor_new_indefinite_bytestring();
    if (indefinite_bytestring_item) {
        size_t bytestring_chunk_count = cbor_bytestring_chunk_count(indefinite_bytestring_item);
        cbor_decref(&indefinite_bytestring_item);
    }

    return 0;
}