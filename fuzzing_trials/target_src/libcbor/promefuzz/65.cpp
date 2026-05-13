// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_string_is_indefinite at strings.c:142:6 in strings.h
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

#include <cstddef>
#include <cstdint>
#include <cstdlib>

static cbor_item_t* create_cbor_item(cbor_type type) {
    cbor_item_t* item = (cbor_item_t*)malloc(sizeof(cbor_item_t));
    if (item) {
        item->type = type;
        item->refcount = 0;
        item->data = nullptr;
    }
    return item;
}

static void initialize_indefinite_string(cbor_item_t* item) {
    if (item && item->type == CBOR_TYPE_STRING) {
        item->data = (unsigned char*)malloc(sizeof(cbor_indefinite_string_data));
        if (item->data) {
            cbor_indefinite_string_data* data = (cbor_indefinite_string_data*)item->data;
            data->chunk_count = 0;
            data->chunk_capacity = 1; // Initialize with some capacity
            data->chunks = (cbor_item_t**)malloc(data->chunk_capacity * sizeof(cbor_item_t*));
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a CBOR item with a random type from the data
    cbor_type type = static_cast<cbor_type>(Data[0] % 8);
    cbor_item_t* item = create_cbor_item(type);

    if (!item) return 0;

    // Fuzz cbor_isa_tag
    bool is_tag = cbor_isa_tag(item);

    // Fuzz cbor_isa_bytestring
    bool is_bytestring = cbor_isa_bytestring(item);

    // Fuzz cbor_isa_string
    bool is_string = cbor_isa_string(item);

    // Fuzz cbor_string_is_indefinite and cbor_string_is_definite
    if (is_string) {
        bool is_indefinite = cbor_string_is_indefinite(item);
        bool is_definite = cbor_string_is_definite(item);
    }

    // Fuzz cbor_string_add_chunk
    if (is_string && cbor_string_is_indefinite(item)) {
        initialize_indefinite_string(item);
        cbor_item_t* chunk = create_cbor_item(CBOR_TYPE_STRING);
        if (chunk) {
            bool added = cbor_string_add_chunk(item, chunk);
            free(chunk);
        }
    }

    if (item->data) {
        free(((cbor_indefinite_string_data*)item->data)->chunks);
        free(item->data);
    }
    free(item);
    return 0;
}