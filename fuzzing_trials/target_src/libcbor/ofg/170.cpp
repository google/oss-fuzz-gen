#include <cstdint>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract a uint16_t value
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Extract a uint16_t value from the input data
    uint16_t value = *(reinterpret_cast<const uint16_t*>(data));

    // Call the function-under-test
    cbor_item_t *item = cbor_build_uint16(value);

    // Clean up if necessary
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}