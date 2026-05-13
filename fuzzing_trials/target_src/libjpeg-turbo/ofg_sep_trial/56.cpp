#include <cstdint>
#include <cstdlib>

extern "C" {
    // Declare the function-under-test
    int tjPlaneHeight(int componentID, int height, int subsamp);
}

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract three integers
    if (size < 3) {
        return 0;
    }

    // Extract three integers from the input data
    int componentID = static_cast<int>(data[0]);
    int height = static_cast<int>(data[1]);
    int subsamp = static_cast<int>(data[2]);

    // Call the function-under-test
    int result = tjPlaneHeight(componentID, height, subsamp);

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile int use_result = result;
    (void)use_result;

    return 0;
}