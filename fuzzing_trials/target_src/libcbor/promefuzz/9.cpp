// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_int16 at ints.c:102:14 in ints.h
// cbor_set_uint16 at ints.c:64:6 in ints.h
// cbor_get_uint16 at ints.c:21:10 in ints.h
// cbor_mark_uint at ints.c:82:6 in ints.h
// cbor_get_int at ints.c:39:10 in ints.h
// cbor_build_uint16 at ints.c:140:14 in ints.h
// cbor_get_uint16 at ints.c:21:10 in ints.h
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
}

#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Use the first two bytes to form a 16-bit integer value
    uint16_t value = static_cast<uint16_t>(Data[0] | (Data[1] << 8));

    // Test cbor_new_int16
    cbor_item_t* item = cbor_new_int16();
    if (item == NULL) return 0;

    // Test cbor_set_uint16
    cbor_set_uint16(item, value);

    // Test cbor_get_uint16
    uint16_t extracted_value = cbor_get_uint16(item);

    // Test cbor_mark_uint
    cbor_mark_uint(item);

    // Test cbor_get_int
    uint64_t int_value = cbor_get_int(item);

    // Clean up
    free(item);

    // Test cbor_build_uint16
    cbor_item_t* built_item = cbor_build_uint16(value);
    if (built_item != NULL) {
        // Test cbor_get_uint16 on built item
        uint16_t built_extracted_value = cbor_get_uint16(built_item);
        
        // Clean up
        free(built_item);
    }

    return 0;
}