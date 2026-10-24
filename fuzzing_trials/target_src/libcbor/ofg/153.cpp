#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a CBOR item from the input data
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Ensure the item is not NULL before proceeding
    if (item != NULL) {
        // Call the function-under-test
        cbor_type type = cbor_typeof(item);

        // Clean up the CBOR item
        cbor_decref(&item);
    }

    return 0;
}