#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Function-under-test declaration
const char * gpsd_packetdump(char *outbuf, size_t outbuflen, const unsigned char *packet, size_t packetlen);

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function-under-test
    size_t outbuflen = 1024; // Define a reasonable buffer length
    char outbuf[outbuflen];  // Output buffer for gpsd_packetdump

    // Ensure the packet is not NULL and has a non-zero size
    if (size == 0) {
        return 0; // No data to process
    }

    // Call the function-under-test
    const char *result = gpsd_packetdump(outbuf, outbuflen, data, size);

    // Use the result to avoid compiler optimizations (optional)
    if (result != NULL) {
        volatile char dummy = result[0];
        (void)dummy;
    }

    return 0;
}