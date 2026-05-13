// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_string at strings.c:13:14 in strings.h
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_bytestring_set_handle at bytestrings.c:71:6 in bytestrings.h
// cbor_serialize_bytestring at serialization.c:232:8 in serialization.h
// cbor_string_is_definite at strings.c:137:6 in strings.h
// cbor_string_handle at strings.c:127:16 in strings.h
// cbor_bytestring_handle at bytestrings.c:17:16 in bytestrings.h
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
#include <cassert>
#include "cbor.h"
#include "strings.h"

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new definite string item
    cbor_item_t *definite_string = cbor_new_definite_string();
    if (!definite_string) return 0;

    // Set the handle to the binary data
    cbor_item_t *bytestring_item = cbor_new_definite_bytestring();
    if (!bytestring_item) {
        cbor_decref(&definite_string);
        return 0;
    }

    // Allocate memory for the data and copy the input data
    cbor_mutable_data data_copy = (cbor_mutable_data)malloc(Size);
    if (!data_copy) {
        cbor_decref(&definite_string);
        cbor_decref(&bytestring_item);
        return 0;
    }
    memcpy(data_copy, Data, Size);

    cbor_bytestring_set_handle(bytestring_item, data_copy, Size);

    // Allocate a buffer for serialization
    size_t buffer_size = Size + 10; // Add some extra space
    cbor_mutable_data buffer = (cbor_mutable_data)malloc(buffer_size);
    if (!buffer) {
        cbor_decref(&definite_string);
        cbor_decref(&bytestring_item);
        return 0;
    }

    // Serialize the bytestring
    size_t serialized_length = cbor_serialize_bytestring(bytestring_item, buffer, buffer_size);

    // Check if the string is definite
    bool is_definite = cbor_string_is_definite(definite_string);

    // Get the handle to the string data
    cbor_mutable_data string_handle = cbor_string_handle(definite_string);

    // Get the handle to the bytestring data
    cbor_mutable_data bytestring_handle = cbor_bytestring_handle(bytestring_item);

    // Clean up
    free(buffer);
    cbor_decref(&definite_string);
    cbor_decref(&bytestring_item);

    return 0;
}