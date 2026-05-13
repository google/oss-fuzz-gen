// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_bytestring_set_handle at bytestrings.c:71:6 in bytestrings.h
// cbor_copy at cbor.c:165:14 in cbor.h
// cbor_decref at common.c:89:6 in common.h
// cbor_copy_definite at cbor.c:303:14 in cbor.h
// cbor_decref at common.c:89:6 in common.h
// cbor_incref at common.c:84:14 in common.h
// cbor_bytestring_is_definite at bytestrings.c:22:6 in bytestrings.h
// cbor_string_is_definite at strings.c:137:6 in strings.h
// cbor_map_is_indefinite at maps.c:118:6 in maps.h
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
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include "strings.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_88(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(cbor_item_t)) {
        return 0;
    }

    cbor_item_t *item = cbor_new_definite_bytestring();
    if (!item) {
        return 0;
    }

    // Copy the input data into the item structure's data field
    cbor_bytestring_set_handle(item, (unsigned char *)Data, Size);

    // Test cbor_copy
    cbor_item_t *copied_item = cbor_copy(item);
    if (copied_item) {
        cbor_decref(&copied_item);
    }

    // Test cbor_copy_definite
    cbor_item_t *copied_definite_item = cbor_copy_definite(item);
    if (copied_definite_item) {
        cbor_decref(&copied_definite_item);
    }

    // Test cbor_incref
    cbor_item_t *incref_item = cbor_incref(item);
    (void)incref_item; // Avoid unused variable warning

    // Test cbor_bytestring_is_definite
    bool is_bytestring_definite = cbor_bytestring_is_definite(item);
    (void)is_bytestring_definite; // Avoid unused variable warning

    // Test cbor_string_is_definite
    bool is_string_definite = cbor_string_is_definite(item);
    (void)is_string_definite; // Avoid unused variable warning

    // Test cbor_map_is_indefinite
    bool is_map_indefinite = cbor_map_is_indefinite(item);
    (void)is_map_indefinite; // Avoid unused variable warning

    // Cleanup
    cbor_decref(&item);

    return 0;
}