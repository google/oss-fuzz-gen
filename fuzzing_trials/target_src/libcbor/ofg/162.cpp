#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a cbor_item_t
    if (size < 1) {
        return 0;
    }

    // Initialize CBOR context
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    if (item != NULL) {
        // Call the function-under-test
        bool is_bytestring = cbor_isa_bytestring(item);

        // Clean up
        cbor_decref(&item);
    }

    return 0;
}