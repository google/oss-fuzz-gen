#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    struct cbor_load_result load_result;
    
    // Ensure that the data is not NULL and size is positive
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test
    cbor_item_t *item = cbor_load(data, size, &load_result);

    // Free the cbor item if it was successfully created
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}