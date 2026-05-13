extern "C" {
#include "cbor.h"
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize the CBOR context
    struct cbor_load_result result;

    // Create a CBOR item from the input data
    cbor_item_t *array = cbor_load(data, size, &result);
    if (array == NULL || !cbor_isa_array(array)) {
        if (array != NULL) {
            cbor_decref(&array);
        }
        return 0;
    }

    // Create a new CBOR item to set in the array
    cbor_item_t *new_item = cbor_new_int8();
    if (new_item == NULL) {
        cbor_decref(&array);
        return 0;
    }
    cbor_set_uint8(new_item, 42); // Set a non-zero value

    // Ensure the index is within the array bounds

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cbor_array_size with cbor_serialized_size
    size_t index = cbor_serialized_size(array) > 0 ? 0 : 0; // Set to a valid index
    // End mutation: Producer.REPLACE_FUNC_MUTATOR



    // Call the function-under-test
    cbor_array_set(array, index, new_item);

    // Clean up
    cbor_decref(&new_item);
    cbor_decref(&array);

    return 0;
}