#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
#include <cstddef>
#include "cstdint"
#include "cstdlib"
#include <cstring>
#include "/src/libcbor/src/cbor/serialization.h"
#include "/src/libcbor/src/cbor/bytestrings.h"
#include "/src/libcbor/src/cbor/strings.h"

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

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

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cbor_new_indefinite_string with cbor_new_indefinite_bytestring
    cbor_item_t* string_item = cbor_new_indefinite_bytestring();
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    if (string_item) {

        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cbor_string_chunk_count with cbor_serialized_size
        size_t chunk_count = cbor_serialized_size(string_item);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR


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