#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was created successfully
    if (item != NULL) {
        // Perform operations on the item if necessary
        // For this fuzzing harness, we will just release the item
        cbor_decref(&item);
    }

    return 0;
}