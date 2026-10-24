extern "C" {
    #include <stdbool.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Initialize a CBOR parser
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item is a valid CBOR item
    if (item != NULL) {
        // Call the function-under-test
        bool is_array = cbor_isa_array(item);

        // Optionally, do something with the result
        // For example, print it (not necessary for fuzzing)
        // printf("Is array: %d\n", is_array);

        // Decrement the reference count of the CBOR item
        cbor_decref(&item);
    }

    return 0;
}