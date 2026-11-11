#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    // Initialize the CBOR context
    struct cbor_load_result load_result;

    // Create a CBOR item from the input data
    cbor_item_t *item = cbor_load(data, size, &load_result);

    // Ensure the item is not NULL and is a bytestring
    if (item == NULL || cbor_isa_bytestring(item) == false) {
        if (item != NULL) {
            cbor_decref(&item);
        }
        return 0;
    }

    // Create a new CBOR bytestring chunk
    cbor_item_t *chunk = cbor_new_definite_bytestring();
    if (chunk == NULL) {
        cbor_decref(&item);
        return 0;
    }

    // Add a small amount of data to the chunk
    uint8_t chunk_data[] = {0x01, 0x02, 0x03, 0x04};
    cbor_bytestring_set_handle(chunk, chunk_data, sizeof(chunk_data));

    // Call the function-under-test
    cbor_bytestring_add_chunk(item, chunk);

    // Decrease the reference count to free the items
    cbor_decref(&item);
    cbor_decref(&chunk);

    return 0;
}