#include <stdint.h>
#include <stddef.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    if (size < sizeof(uint16_t)) {
        return 0; // Not enough data to extract a uint16_t
    }

    // Extract a uint16_t from the input data
    uint16_t value = *(reinterpret_cast<const uint16_t*>(data));

    // Call the function-under-test
    cbor_item_t *item = cbor_build_uint16(value);

    // Clean up the created CBOR item
    cbor_decref(&item);

    return 0;
}