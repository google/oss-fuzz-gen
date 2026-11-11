// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_indefinite_array at arrays.c:123:14 in arrays.h
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_decref at common.c:89:6 in common.h
// cbor_bytestring_set_handle at bytestrings.c:71:6 in bytestrings.h
// cbor_bytestring_handle at bytestrings.c:17:16 in bytestrings.h
// cbor_array_push at arrays.c:49:6 in arrays.h
// cbor_copy at cbor.c:165:14 in cbor.h
// cbor_decref at common.c:89:6 in common.h
// cbor_isa_array at common.c:44:6 in common.h
// cbor_is_undef at common.c:75:6 in common.h
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
#include <cbor.h>
// #include <cbor.h>
// #include <cbor.h>
// #include <arrays.h>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new indefinite array
    cbor_item_t *array = cbor_new_indefinite_array();
    if (!array) return 0;

    // Create a CBOR item as a definite byte string
    cbor_item_t *item = cbor_new_definite_bytestring();
    if (!item) {
        cbor_decref(&array);
        return 0;
    }
    cbor_bytestring_set_handle(item, (cbor_mutable_data)malloc(Size), Size);
    memcpy(cbor_bytestring_handle(item), Data, Size);

    // Test cbor_array_push
    cbor_array_push(array, item);

    // Test cbor_copy
    cbor_item_t *copy = cbor_copy(array);
    if (copy) {
        cbor_decref(&copy);
    }

    // Test cbor_isa_array
    bool is_array = cbor_isa_array(array);

    // Test cbor_is_undef
    bool is_undef = cbor_is_undef(item);

    // Cleanup
    cbor_decref(&array);
    cbor_decref(&item);

    return 0;
}