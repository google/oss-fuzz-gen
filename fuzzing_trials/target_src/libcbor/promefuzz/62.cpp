// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_string at strings.c:13:14 in strings.h
// cbor_string_is_definite at strings.c:137:6 in strings.h
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
#include "strings.h"
}

#include <cstdint>
#include <cstdlib>

static cbor_item_t* create_cbor_item(cbor_type type) {
    cbor_item_t* item = cbor_new_definite_string();
    if (item) {
        item->type = type;
    }
    return item;
}

static void destroy_cbor_item(cbor_item_t* item) {
    cbor_decref(&item);
}

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a CBOR item with a random type based on the input data
    cbor_type item_type = static_cast<cbor_type>(Data[0] % 8);
    cbor_item_t* item = create_cbor_item(item_type);
    if (!item) return 0;

    // Test cbor_isa_tag
    bool is_tag = cbor_isa_tag(item);

    // Test cbor_isa_bytestring
    bool is_bytestring = cbor_isa_bytestring(item);

    // Test cbor_isa_string
    bool is_string = cbor_isa_string(item);

    // Test cbor_string_is_definite and cbor_string_is_indefinite
    if (is_string) {
        bool is_definite = cbor_string_is_definite(item);
        bool is_indefinite = cbor_string_is_indefinite(item);

        // If the string is indefinite, try adding a chunk
        if (is_indefinite && Size > 1) {
            cbor_item_t* chunk = create_cbor_item(CBOR_TYPE_STRING);
            if (chunk) {
                cbor_string_add_chunk(item, chunk);
                destroy_cbor_item(chunk);
            }
        }
    }

    destroy_cbor_item(item);
    return 0;
}