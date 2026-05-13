// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_indefinite_bytestring at bytestrings.c:42:14 in bytestrings.h
// cbor_build_bytestring at bytestrings.c:61:14 in bytestrings.h
// cbor_decref at common.c:89:6 in common.h
// cbor_string_add_chunk at strings.c:95:6 in strings.h
// cbor_incref at common.c:84:14 in common.h
// cbor_serialize at serialization.c:20:8 in serialization.h
// cbor_copy at cbor.c:165:14 in cbor.h
// cbor_serialize at serialization.c:20:8 in serialization.h
// cbor_decref at common.c:89:6 in common.h
// cbor_typeof at common.c:22:11 in common.h
// cbor_decref at common.c:89:6 in common.h
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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include "strings.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new indefinite bytestring
    cbor_item_t *indefinite_bytestring = cbor_new_indefinite_bytestring();
    if (!indefinite_bytestring) return 0;

    // Create a definite bytestring chunk from the input data
    cbor_item_t *chunk = cbor_build_bytestring(Data, Size);
    if (!chunk) {
        cbor_decref(&indefinite_bytestring);
        return 0;
    }

    // Add the chunk to the indefinite bytestring
    cbor_string_add_chunk(indefinite_bytestring, chunk);

    // Increment reference count of the chunk
    cbor_incref(chunk);

    // Serialize the indefinite bytestring
    unsigned char buffer[1024];
    cbor_serialize(indefinite_bytestring, buffer, sizeof(buffer));

    // Copy the indefinite bytestring
    cbor_item_t *copy = cbor_copy(indefinite_bytestring);
    if (copy) {
        // Serialize the copied item
        cbor_serialize(copy, buffer, sizeof(buffer));
        cbor_decref(&copy);
    }

    // Check the type of the indefinite bytestring
    cbor_type type = cbor_typeof(indefinite_bytestring);

    // Cleanup
    cbor_decref(&chunk);
    cbor_decref(&indefinite_bytestring);

    return 0;
}