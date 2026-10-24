extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to create a valid array size
    if (size == 0) {
        return 0;
    }

    // Use the size from the input data to create a definite array
    size_t array_size = static_cast<size_t>(data[0]); // Use first byte for size

    // Call the function-under-test
    cbor_item_t *array = cbor_new_definite_array(array_size);

    // Check if the array was created successfully
    if (array != NULL) {
        // Perform operations on the array if needed
        // ...

        // Free the allocated array
        cbor_decref(&array);
    }

    return 0;
}