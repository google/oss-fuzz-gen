#include <cstdint>
#include <cbor.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Ensure that there is at least one byte of data to use
    if (size < 1) {
        return 0;
    }

    // Create a CBOR array to use more of the input data
    cbor_item_t *array = cbor_new_definite_array(size);

    // Fill the array with control items from the input data
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *ctrl_item = cbor_build_ctrl(data[i]);
        cbor_array_push(array, ctrl_item);
        cbor_decref(&ctrl_item);  // Decrease reference count to avoid memory leak
    }

    // Clean up the created CBOR array to avoid memory leaks
    cbor_decref(&array);

    return 0;
}