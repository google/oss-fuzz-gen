#include <cstdint>
#include <cstddef>  // Include this for size_t

// Function-under-test declaration
extern "C" unsigned long TJBUFSIZE(int width, int height);

extern "C" int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Ensure that there is enough data to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract two integers from the input data
    int width = static_cast<int>(data[0]);
    int height = static_cast<int>(data[1]);

    // Call the function-under-test
    unsigned long result = TJBUFSIZE(width, height);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

    return 0;
}