#include <cstddef>
#include <cstdint>
#include <string>

// Assuming the function-under-test is part of a C library
extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h" // Correct path to the header where lou_getTypeformForEmphClass is declared
    formtype lou_getTypeformForEmphClass(const char *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create two non-null strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two string parameters
    size_t mid = size / 2;
    std::string param1(reinterpret_cast<const char*>(data), mid);
    std::string param2(reinterpret_cast<const char*>(data + mid), size - mid);

    // Call the function-under-test
    formtype result = lou_getTypeformForEmphClass(param1.c_str(), param2.c_str());

    // Use the result in some way to prevent the compiler from optimizing the call away
    volatile formtype use_result = result;
    (void)use_result;

    return 0;
}