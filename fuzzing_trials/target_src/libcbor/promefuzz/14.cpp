// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_indefinite_bytestring at bytestrings.c:42:14 in bytestrings.h
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_bytestring_set_handle at bytestrings.c:71:6 in bytestrings.h
// cbor_bytestring_is_indefinite at bytestrings.c:27:6 in bytestrings.h
// cbor_bytestring_add_chunk at bytestrings.c:92:6 in bytestrings.h
// cbor_bytestring_chunks_handle at bytestrings.c:80:15 in bytestrings.h
// cbor_new_indefinite_string at strings.c:25:14 in strings.h
// cbor_string_is_indefinite at strings.c:142:6 in strings.h
// cbor_string_add_chunk at strings.c:95:6 in strings.h
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
#include "strings.h"
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create an indefinite byte string
    cbor_item_t* indefinite_bytestring = cbor_new_indefinite_bytestring();
    if (!indefinite_bytestring) return 0;

    // Create a definite byte string chunk
    cbor_item_t* definite_bytestring_chunk = cbor_new_definite_bytestring();
    if (!definite_bytestring_chunk) {
        cbor_decref(&indefinite_bytestring);
        return 0;
    }

    // Set the data to the definite bytestring chunk
    unsigned char* chunk_data = (unsigned char*)malloc(Size);
    if (!chunk_data) {
        cbor_decref(&indefinite_bytestring);
        cbor_decref(&definite_bytestring_chunk);
        return 0;
    }
    memcpy(chunk_data, Data, Size);
    cbor_bytestring_set_handle(definite_bytestring_chunk, chunk_data, Size);

    // Check if the item is a bytestring
    if (cbor_isa_bytestring(indefinite_bytestring)) {
        // Check if the bytestring is indefinite
        if (cbor_bytestring_is_indefinite(indefinite_bytestring)) {
            // Add chunk to the indefinite bytestring
            cbor_bytestring_add_chunk(indefinite_bytestring, definite_bytestring_chunk);
        }

        // Retrieve chunks handle
        cbor_item_t** chunks = cbor_bytestring_chunks_handle(indefinite_bytestring);
        (void)chunks; // Use chunks as needed or just to ensure no-unused warning
    }

    // Create an indefinite string
    cbor_item_t* indefinite_string = cbor_new_indefinite_string();
    if (!indefinite_string) {
        cbor_decref(&indefinite_bytestring);
        cbor_decref(&definite_bytestring_chunk);
        return 0;
    }

    // Check if the string is indefinite
    if (cbor_string_is_indefinite(indefinite_string)) {
        // Add chunk to the indefinite string
        cbor_string_add_chunk(indefinite_string, definite_bytestring_chunk);
    }

    // Cleanup
    cbor_decref(&indefinite_bytestring);
    cbor_decref(&definite_bytestring_chunk);
    cbor_decref(&indefinite_string);

    return 0;
}