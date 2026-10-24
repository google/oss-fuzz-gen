#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Check if the input data is large enough to be a valid CBOR item
    if (size == 0) {
        return 0;
    }

    // Attempt to parse the input data into a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // If parsing fails, exit early
    if (item == NULL) {
        return 0;
    }

    // Allocate memory for the output buffer
    unsigned char *buffer = static_cast<unsigned char *>(malloc(size));
    if (buffer == NULL) {
        cbor_decref(&item);
        return 0;
    }

    // Call the function-under-test
    size_t serialized_size = cbor_serialize(item, buffer, size);

    // Clean up
    free(buffer);
    cbor_decref(&item);

    return 0;
}