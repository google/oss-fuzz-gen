// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_string at strings.c:13:14 in strings.h
// cbor_build_stringn at strings.c:55:14 in strings.h
// cbor_string_length at strings.c:122:8 in strings.h
// cbor_string_codepoint_count at strings.c:132:8 in strings.h
// cbor_serialize_string at serialization.c:264:8 in serialization.h
// cbor_string_set_handle at strings.c:65:6 in strings.h
// cbor_serialize_string at serialization.c:264:8 in serialization.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "cbor.h"
#include "strings.h"

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a new definite string item
    cbor_item_t* item = cbor_new_definite_string();
    if (!item) return 0;

    // Use cbor_build_stringn to create a string item with the input data
    cbor_item_t* built_item = cbor_build_stringn(reinterpret_cast<const char*>(Data), Size);
    if (built_item) {
        // Get the string length
        size_t length = cbor_string_length(built_item);

        // Get the codepoint count
        size_t codepoints = cbor_string_codepoint_count(built_item);

        // Attempt to serialize the string
        uint8_t buffer[1024]; // Arbitrary buffer size for testing
        size_t serialized_length = cbor_serialize_string(built_item, buffer, sizeof(buffer));

        // Clean up
        cbor_decref(&built_item);
    }

    // Duplicate the data to ensure proper ownership for cbor_string_set_handle
    uint8_t* data_copy = static_cast<uint8_t*>(malloc(Size));
    if (data_copy) {
        memcpy(data_copy, Data, Size);

        // Set handle with the copied data
        cbor_string_set_handle(item, data_copy, Size);

        // Attempt to serialize the string
        uint8_t buffer[1024]; // Arbitrary buffer size for testing
        size_t serialized_length = cbor_serialize_string(item, buffer, sizeof(buffer));
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}