#include <cbor.h>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include for memcpy

extern "C" {
    // Function-under-test
    void cbor_set_float4(cbor_item_t *item, float value);
    cbor_item_t *cbor_new_float4();
    void cbor_decref(cbor_item_t **item);
    double cbor_float_get_float(const cbor_item_t *item); // Corrected to match the actual function signature
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract a float
    if (size < sizeof(float)) {
        return 0;
    }

    // Initialize a cbor_item_t object
    cbor_item_t *item = cbor_new_float4();
    if (item == nullptr) {
        return 0;
    }

    // Extract a float value from the input data
    float value;
    memcpy(&value, data, sizeof(float));

    // Call the function-under-test
    cbor_set_float4(item, value);

    // Additional logic to increase code coverage
    // Check the state of the item after setting the float
    if (static_cast<float>(cbor_float_get_float(item)) == value) {
        // Do something or assert, if necessary
        // For example, just a dummy operation to ensure the branch is covered
        volatile int dummy = 0;
        dummy++;
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}