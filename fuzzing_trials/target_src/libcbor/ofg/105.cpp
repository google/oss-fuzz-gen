#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>

// Ensure the cbor_intermediate_decref function is correctly linked from C
extern "C" {
    void cbor_intermediate_decref(cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    // Initialize a cbor_item_t pointer
    cbor_item_t *item = cbor_new_definite_array(1);

    // Ensure the item is not NULL
    if (item != NULL) {
        // Add a dummy value to the array to avoid it being empty
        cbor_array_push(item, cbor_build_uint8(data[0])); 

        // Call the function-under-test
        cbor_intermediate_decref(item);
    }

    return 0;
}