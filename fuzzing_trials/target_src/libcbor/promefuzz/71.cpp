// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_array at arrays.c:102:14 in arrays.h
// cbor_serialize_array at serialization.c:296:8 in serialization.h
// cbor_array_handle at arrays.c:97:15 in arrays.h
// cbor_array_size at arrays.c:13:8 in arrays.h
// cbor_array_allocated at arrays.c:18:8 in arrays.h
// cbor_array_get at arrays.c:23:14 in arrays.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <cassert>
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    // Extract a size for the new array
    size_t array_size = *(reinterpret_cast<const size_t*>(Data));
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    // Create a new definite array
    cbor_item_t* array = cbor_new_definite_array(array_size);
    if (!array) return 0;

    // Attempt to serialize the array into a buffer
    uint8_t buffer[1024];
    size_t serialized_length = cbor_serialize_array(array, buffer, sizeof(buffer));

    // Retrieve the handle to the array's contents
    cbor_item_t** handle = cbor_array_handle(array);

    // Get the size and allocated size of the array
    size_t size = cbor_array_size(array);
    size_t allocated = cbor_array_allocated(array);

    // Try to access each element in the array
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t* item = cbor_array_get(array, i);
        if (item) {
            cbor_decref(&item);
        }
    }

    // Clean up
    cbor_decref(&array);

    return 0;
}