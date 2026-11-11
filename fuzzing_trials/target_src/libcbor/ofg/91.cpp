extern "C" {
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the string and ensure it's null-terminated
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0;
    }

    // Copy the data into the string buffer
    memcpy(str, data, size);
    str[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    cbor_item_t *item = cbor_build_stringn(str, size);

    // Free the allocated memory
    free(str);

    // If the item is not NULL, free it
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}