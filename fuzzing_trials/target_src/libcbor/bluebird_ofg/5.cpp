#include "cbor.h"
#include "cstdio"
#include "cstdlib"
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize a cbor_item_t pointer
    cbor_item_t *item = cbor_new_definite_bytestring();

    // Ensure the item is not NULL
    if (item == NULL) {
        return 0;
    }

    // Set the content of the CBOR item to the fuzz data
    unsigned char *item_data = (unsigned char *)malloc(size);
    if (item_data == NULL) {
        cbor_decref(&item);
        return 0;
    }
    memcpy(item_data, data, size);
    cbor_bytestring_set_handle(item, item_data, size);

    // Open a temporary file to pass as the FILE* parameter
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        cbor_decref(&item);
        // No need to free item_data here, as cbor_bytestring_set_handle transfers ownership
        return 0;
    }

    // Call the function-under-test
    cbor_describe(item, temp_file);

    // Clean up
    cbor_decref(&item);
    fclose(temp_file);

    return 0;
}