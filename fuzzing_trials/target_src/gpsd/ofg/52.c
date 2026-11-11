#include <stdint.h>
#include <stddef.h>

// Assuming isgps30bits_t is a typedef for a 32-bit unsigned integer
typedef uint32_t isgps30bits_t;

// Function-under-test
unsigned int isgps_parity(isgps30bits_t bits);

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure we have enough data to form an isgps30bits_t
    if (size < sizeof(isgps30bits_t)) {
        return 0;
    }

    // Construct an isgps30bits_t from the input data
    isgps30bits_t bits = 0;
    for (size_t i = 0; i < sizeof(isgps30bits_t); ++i) {
        bits |= ((isgps30bits_t)data[i]) << (i * 8);
    }

    // Call the function-under-test
    unsigned int result = isgps_parity(bits);

    // Use the result to prevent the compiler from optimizing the call away
    (void)result;

    return 0;
}