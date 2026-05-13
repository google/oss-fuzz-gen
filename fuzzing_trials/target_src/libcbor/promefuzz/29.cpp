// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_tag at tags.c:10:14 in tags.h
// cbor_tag_value at tags.c:31:10 in tags.h
// cbor_new_tag at tags.c:10:14 in tags.h
// cbor_tag_set_item at tags.c:36:6 in tags.h
// cbor_tag_item at tags.c:23:14 in tags.h
// cbor_build_tag at tags.c:45:14 in tags.h
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
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    uint64_t tag_value = *reinterpret_cast<const uint64_t*>(Data);
    cbor_item_t* tag_item = cbor_new_tag(tag_value);

    if (tag_item) {
        // Test cbor_refcount
        size_t refcount = cbor_refcount(tag_item);

        // Test cbor_tag_value
        uint64_t retrieved_tag_value = cbor_tag_value(tag_item);

        // Test cbor_tag_set_item
        cbor_item_t* new_item = cbor_new_tag(tag_value + 1); // create a new item to associate
        if (new_item) {
            cbor_tag_set_item(tag_item, new_item);
            cbor_decref(&new_item); // Decrease reference count for new_item
        }

        // Test cbor_tag_item
        cbor_item_t* associated_item = cbor_tag_item(tag_item);
        if (associated_item) {
            cbor_decref(&associated_item); // Decrease reference count for associated_item
        }

        // Test cbor_build_tag
        cbor_item_t* built_tag = cbor_build_tag(tag_value, tag_item);
        if (built_tag) {
            cbor_decref(&built_tag); // Decrease reference count for built_tag
        }

        cbor_decref(&tag_item); // Decrease reference count for tag_item
    }

    return 0;
}