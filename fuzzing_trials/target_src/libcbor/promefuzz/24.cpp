// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_indefinite_bytestring at bytestrings.c:42:14 in bytestrings.h
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_bytestring_set_handle at bytestrings.c:71:6 in bytestrings.h
// cbor_bytestring_is_indefinite at bytestrings.c:27:6 in bytestrings.h
// cbor_bytestring_add_chunk at bytestrings.c:92:6 in bytestrings.h
// cbor_string_chunk_count at strings.c:89:8 in strings.h
// cbor_bytestring_length at bytestrings.c:12:8 in bytestrings.h
// cbor_bytestring_is_indefinite at bytestrings.c:27:6 in bytestrings.h
// cbor_bytestring_is_indefinite at bytestrings.c:27:6 in bytestrings.h
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
extern "C" {
#include "cbor.h"
#include "strings.h"
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

static cbor_item_t* create_indefinite_bytestring() {
    cbor_item_t* item = cbor_new_indefinite_bytestring();
    if (item) {
        item->type = CBOR_TYPE_BYTESTRING;
    }
    return item;
}

static cbor_item_t* create_definite_bytestring(const uint8_t* data, size_t length) {
    cbor_item_t* item = cbor_new_definite_bytestring();
    if (item) {
        item->type = CBOR_TYPE_BYTESTRING;
        // Allocate memory for the data to ensure it matches the deallocation method
        cbor_mutable_data allocated_data = (cbor_mutable_data)malloc(length);
        if (allocated_data) {
            memcpy(allocated_data, data, length);
            cbor_bytestring_set_handle(item, allocated_data, length);
        } else {
            cbor_decref(&item);
            return nullptr;
        }
    }
    return item;
}

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create an indefinite bytestring item
    cbor_item_t* indefinite_item = create_indefinite_bytestring();
    if (!indefinite_item) return 0;

    // Create a definite bytestring chunk
    cbor_item_t* definite_chunk = create_definite_bytestring(Data, Size);
    if (!definite_chunk) {
        cbor_decref(&indefinite_item);
        return 0;
    }

    // Test cbor_bytestring_add_chunk
    if (cbor_bytestring_is_indefinite(indefinite_item)) {
        cbor_bytestring_add_chunk(indefinite_item, definite_chunk);
    }

    // Test cbor_string_chunk_count
    if (indefinite_item->type == CBOR_TYPE_STRING) {
        cbor_string_chunk_count(indefinite_item);
    }

    // Test cbor_bytestring_length
    if (definite_chunk->type == CBOR_TYPE_BYTESTRING) {
        cbor_bytestring_length(definite_chunk);
    }

    // Test cbor_bytestring_is_indefinite
    cbor_bytestring_is_indefinite(definite_chunk);

    // Test cbor_bytestring_chunk_count
    if (cbor_bytestring_is_indefinite(indefinite_item)) {
        cbor_bytestring_chunk_count(indefinite_item);
    }

    // Cleanup
    cbor_decref(&indefinite_item);
    cbor_decref(&definite_chunk);

    return 0;
}