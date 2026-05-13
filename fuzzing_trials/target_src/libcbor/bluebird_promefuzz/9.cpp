#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
#include "cstdint"
#include "cstdlib"
#include <cstring>
#include "cbor.h"
#include "/src/libcbor/src/cbor/common.h"
#include "/src/libcbor/src/cbor/floats_ctrls.h"
#include "/src/libcbor/src/cbor/bytestrings.h"

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

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

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cbor_copy to cbor_serialize

        size_t ret_cbor_serialize_tngjj = cbor_serialize(item, (unsigned char *)Data, 1);
        if (ret_cbor_serialize_tngjj < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

        cbor_decref(&item);
    }

    // Test cbor_new_definite_bytestring

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cbor_new_definite_bytestring with cbor_new_indefinite_string
    cbor_item_t *bytestring_item = cbor_new_indefinite_string();
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


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