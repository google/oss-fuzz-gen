// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// _cbor_map_add_key at maps.c:52:6 in maps.h
// _cbor_map_add_value at maps.c:95:6 in maps.h
// cbor_map_allocated at maps.c:16:8 in maps.h
// cbor_tag_set_item at tags.c:36:6 in tags.h
// cbor_map_add at maps.c:107:6 in maps.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include <cstddef>
#include <cstdint>
#include <cstdlib>

static cbor_item_t* create_map_item() {
    cbor_item_t* item = static_cast<cbor_item_t*>(malloc(sizeof(cbor_item_t)));
    if (item) {
        item->type = CBOR_TYPE_MAP;
        item->refcount = 1;
        item->data = nullptr; // Initialize data to nullptr
        memset(&item->metadata, 0, sizeof(item->metadata)); // Zero initialize metadata
    }
    return item;
}

static cbor_item_t* create_key_item() {
    cbor_item_t* item = static_cast<cbor_item_t*>(malloc(sizeof(cbor_item_t)));
    if (item) {
        item->type = CBOR_TYPE_STRING; // Assuming key is a string for simplicity
        item->refcount = 1;
        item->data = nullptr; // Initialize data to nullptr
        memset(&item->metadata, 0, sizeof(item->metadata)); // Zero initialize metadata
    }
    return item;
}

static cbor_item_t* create_value_item() {
    cbor_item_t* item = static_cast<cbor_item_t*>(malloc(sizeof(cbor_item_t)));
    if (item) {
        item->type = CBOR_TYPE_UINT; // Assuming value is an unsigned integer for simplicity
        item->refcount = 1;
        item->data = nullptr; // Initialize data to nullptr
        memset(&item->metadata, 0, sizeof(item->metadata)); // Zero initialize metadata
    }
    return item;
}

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Not enough data to proceed

    cbor_item_t* map = create_map_item();
    cbor_item_t* key = create_key_item();
    cbor_item_t* value = create_value_item();

    if (!map || !key || !value) {
        free(map);
        free(key);
        free(value);
        return 0;
    }

    // Fuzzing _cbor_map_add_key
    if (_cbor_map_add_key(map, key)) {
        // Fuzzing _cbor_map_add_value
        _cbor_map_add_value(map, value);
    }

    // Fuzzing cbor_map_allocated
    size_t allocated_size = cbor_map_allocated(map);

    // Fuzzing cbor_tag_set_item
    cbor_item_t* tag = create_map_item(); // Reuse map creation for a tag
    if (tag) {
        cbor_tag_set_item(tag, map);
    }

    // Fuzzing cbor_map_add
    struct cbor_pair pair = {key, value};
    cbor_map_add(map, pair);

    // Cleanup
    cbor_intermediate_decref(map);
    cbor_intermediate_decref(key);
    cbor_intermediate_decref(value);
    if (tag) {
        cbor_intermediate_decref(tag);
    }

    return 0;
}