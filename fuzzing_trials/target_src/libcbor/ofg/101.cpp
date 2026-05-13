#include <cbor.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a C string
    if (size == 0) {
        return 0;
    }

    // Allocate a buffer for the string and null-terminate it
    char *cstr = new char[size + 1];
    std::memcpy(cstr, data, size);
    cstr[size] = '\0';

    // Call the function-under-test
    cbor_item_t *item = cbor_build_string(cstr);

    // Cleanup
    delete[] cstr;
    if (item != nullptr) {
        cbor_decref(&item);
    }

    return 0;
}