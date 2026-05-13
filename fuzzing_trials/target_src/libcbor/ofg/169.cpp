#include <cstdint>
#include <cbor.h>

extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize CBOR parser
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    if (item == NULL) {
        return 0;
    }

    // Check if the item is a string type before calling cbor_string_chunk_count
    if (cbor_isa_string(item)) {
        // Call the function-under-test
        size_t chunk_count = cbor_string_chunk_count(item);
    }

    // Cleanup
    cbor_decref(&item);

    return 0;
}