// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_load at cbor.c:16:14 in cbor.h
// cbor_copy at cbor.c:165:14 in cbor.h
// cbor_intermediate_decref at common.c:160:6 in common.h
// cbor_decref at common.c:89:6 in common.h
// cbor_new_definite_bytestring at bytestrings.c:31:14 in bytestrings.h
// cbor_intermediate_decref at common.c:160:6 in common.h
// cbor_new_undef at floats_ctrls.c:156:14 in floats_ctrls.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Attempt to load the data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(Data, Size, &result);

    if (item != NULL) {
        // Test cbor_copy
        cbor_item_t *copied_item = cbor_copy(item);
        if (copied_item != NULL) {
            cbor_intermediate_decref(copied_item);
        }

        // Test cbor_decref
        cbor_decref(&item);
    }

    // Test cbor_new_definite_bytestring
    cbor_item_t *bytestring_item = cbor_new_definite_bytestring();
    if (bytestring_item != NULL) {
        cbor_intermediate_decref(bytestring_item);
    }

    // Test cbor_new_undef
    cbor_item_t *undef_item = cbor_new_undef();
    if (undef_item != NULL) {
        cbor_intermediate_decref(undef_item);
    }

    return 0;
}