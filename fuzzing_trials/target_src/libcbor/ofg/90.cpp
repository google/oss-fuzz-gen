#include <cbor.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Ensure there is data to process
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the string, ensuring it's null-terminated
    char *str = new char[size + 1];
    memcpy(str, data, size);
    str[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    cbor_item_t *item = cbor_build_stringn(str, size);

    // Clean up
    delete[] str;
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}