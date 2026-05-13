#include <stdint.h>
#include <cbor.h>

extern "C" {
    bool cbor_is_float(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Initialize a CBOR item from the input data
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was successfully created
    if (item != NULL) {
        // Call the function-under-test
        bool is_float = cbor_is_float(item);

        // Clean up the CBOR item
        cbor_decref(&item);
    }

    return 0;
}