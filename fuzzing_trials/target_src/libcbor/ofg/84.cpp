#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Check if size is sufficient to create a meaningful CBOR item
    if (size == 0) {
        return 0;
    }

    // Create a new CBOR array with space for 1 item
    cbor_item_t *array_item = cbor_new_definite_array(1);

    // Ensure array_item is not NULL
    if (array_item == NULL) {
        return 0;
    }

    // Create a CBOR bytestring from the input data
    cbor_item_t *data_item = cbor_build_bytestring(data, size);

    // Ensure data_item is not NULL
    if (data_item == NULL) {
        cbor_decref(&array_item);
        return 0;
    }

    // Add the data_item to the array_item
    bool result = cbor_array_push(array_item, data_item);

    // Call the function-under-test
    // Here you would call the actual function you want to test with the array_item
    // For example: some_function_under_test(array_item);

    // Clean up
    cbor_decref(&array_item);
    cbor_decref(&data_item);

    return 0;
}