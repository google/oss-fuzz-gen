#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Check if the input size is appropriate for the function under test
    if (size == 0) {
        return 0;
    }

    // Attempt to parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Perform any necessary cleanup
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}