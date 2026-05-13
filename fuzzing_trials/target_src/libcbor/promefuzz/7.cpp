// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_array at arrays.c:102:14 in arrays.h
// cbor_new_definite_array at arrays.c:102:14 in arrays.h
// cbor_array_push at arrays.c:49:6 in arrays.h
// cbor_decref at common.c:89:6 in common.h
// cbor_refcount at common.c:162:8 in common.h
// cbor_copy_definite at cbor.c:303:14 in cbor.h
// cbor_decref at common.c:89:6 in common.h
// cbor_isa_map at common.c:48:6 in common.h
// cbor_map_size at maps.c:11:8 in maps.h
// cbor_array_size at arrays.c:13:8 in arrays.h
// cbor_serialized_size at serialization.c:64:8 in serialization.h
// cbor_decref at common.c:89:6 in common.h
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
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    // Prepare a dummy CBOR item
    cbor_item_t* item = cbor_new_definite_array(Size);
    if (!item) return 0;

    // Use the data to fill the array with dummy items
    for (size_t i = 0; i < Size; ++i) {
        cbor_item_t* dummy_item = cbor_new_definite_array(0);
        if (!dummy_item) break;
        cbor_array_push(item, dummy_item);
        // Decrease the reference count of the dummy item to prevent memory leak
        cbor_decref(&dummy_item);
    }

    // Test cbor_refcount
    size_t refcount = cbor_refcount(item);

    // Test cbor_copy_definite
    cbor_item_t* copied_item = cbor_copy_definite(item);
    if (copied_item) {
        cbor_decref(&copied_item);
    }

    // Test cbor_map_size
    // Since item is an array, this should trigger an assertion in real usage
    // but for fuzzing, we will just call it to see if it behaves unexpectedly
    size_t map_size = 0;
    if (cbor_isa_map(item)) {
        map_size = cbor_map_size(item);
    }

    // Test cbor_array_size
    size_t array_size = cbor_array_size(item);

    // Test cbor_serialized_size
    size_t serialized_size = cbor_serialized_size(item);

    // Cleanup
    cbor_decref(&item);

    return 0;
}