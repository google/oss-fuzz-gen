#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Initialize a CBOR parser
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the loaded item is a valid CBOR array
    if (item != NULL && cbor_isa_array(item)) {
        // Call the function-under-test
        cbor_item_t **array_handle = cbor_array_handle(item);

        // Perform some basic validation on the returned handle
        if (array_handle != NULL) {
            size_t array_size = cbor_array_size(item);
            for (size_t i = 0; i < array_size; ++i) {
                // Access each element to ensure the handle is functioning
                cbor_item_t *element = array_handle[i];
                // Further processing can be done on the element if needed
            }
        }
    }

    // Clean up the CBOR item
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}