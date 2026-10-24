// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_build_uint64 at ints.c:156:14 in ints.h
// cbor_refcount at common.c:162:8 in common.h
// cbor_set_uint32 at ints.c:70:6 in ints.h
// cbor_serialized_size at serialization.c:64:8 in serialization.h
// cbor_copy_definite at cbor.c:303:14 in cbor.h
// cbor_intermediate_decref at common.c:160:6 in common.h
// cbor_intermediate_decref at common.c:160:6 in common.h
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
#include "cbor.h"
#include "cbor.h"
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a CBOR item using the first byte of the input data
    cbor_item_t *item = cbor_build_uint64(Data[0]);
    if (!item) return 0;

    // Fuzz cbor_refcount
    size_t refcount = cbor_refcount(item);

    // Fuzz cbor_set_uint32 with a random uint32_t value from the input
    if (Size >= 5) {
        uint32_t value = *(reinterpret_cast<const uint32_t*>(Data + 1));
        cbor_set_uint32(item, value);
    }

    // Fuzz cbor_serialized_size
    size_t serialized_size = cbor_serialized_size(item);

    // Fuzz cbor_copy_definite
    cbor_item_t *copied_item = cbor_copy_definite(item);
    if (copied_item) {
        // Fuzz cbor_intermediate_decref on copied item
        cbor_intermediate_decref(copied_item);
    }

    // Fuzz cbor_intermediate_decref on original item
    cbor_intermediate_decref(item);

    return 0;
}