// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_string_is_indefinite at strings.c:142:6 in strings.h
// cbor_map_is_indefinite at maps.c:118:6 in maps.h
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

#include <cstdint>
#include <cstring>

static cbor_item_t* create_cbor_item(cbor_type type) {
    cbor_item_t* item = static_cast<cbor_item_t*>(malloc(sizeof(cbor_item_t)));
    if (!item) return nullptr;
    item->type = type;
    item->refcount = 1;
    item->data = nullptr;
    memset(&item->metadata, 0, sizeof(item->metadata));
    return item;
}

static cbor_item_t* create_indefinite_string_item() {
    cbor_item_t* item = create_cbor_item(CBOR_TYPE_STRING);
    if (!item) return nullptr;
    item->data = static_cast<unsigned char*>(malloc(sizeof(cbor_indefinite_string_data)));
    if (!item->data) {
        free(item);
        return nullptr;
    }
    cbor_indefinite_string_data* data = reinterpret_cast<cbor_indefinite_string_data*>(item->data);
    data->chunk_count = 0;
    data->chunk_capacity = 1;
    data->chunks = static_cast<cbor_item_t**>(malloc(sizeof(cbor_item_t*) * data->chunk_capacity));
    if (!data->chunks) {
        free(item->data);
        free(item);
        return nullptr;
    }
    return item;
}

static void free_cbor_item(cbor_item_t* item) {
    if (item) {
        if (item->type == CBOR_TYPE_STRING && item->data) {
            cbor_indefinite_string_data* data = reinterpret_cast<cbor_indefinite_string_data*>(item->data);
            free(data->chunks);
        }
        free(item->data);
        free(item);
    }
}

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cbor_item_t* item = create_cbor_item(static_cast<cbor_type>(Data[0] % 8));
    if (!item) return 0;

    bool result1 = cbor_string_is_indefinite(item);
    bool result2 = cbor_isa_tag(item);
    bool result3 = cbor_isa_bytestring(item);
    bool result4 = cbor_map_is_indefinite(item);
    bool result5 = cbor_isa_string(item);

    // Create a chunk to add if item is an indefinite string
    cbor_item_t* chunk = nullptr;
    if (item->type == CBOR_TYPE_STRING && cbor_string_is_indefinite(item)) {
        chunk = create_cbor_item(CBOR_TYPE_STRING);
        if (chunk) {
            cbor_string_add_chunk(item, chunk);
        }
    }

    free_cbor_item(chunk);
    free_cbor_item(item);

    return 0;
}