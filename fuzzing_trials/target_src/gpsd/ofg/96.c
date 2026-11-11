#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assuming these structures are defined somewhere in the GPSD project
struct gps_context_t {
    // Placeholder for actual structure members
    int dummy;
};

struct rtcm3_t {
    // Placeholder for actual structure members
    int dummy;
};

// Function signature to fuzz
void rtcm3_unpack(const struct gps_context_t *context, struct rtcm3_t *rtcm3, const unsigned char *data);

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Initialize the gps_context_t structure
    struct gps_context_t context;
    context.dummy = 1; // Initialize with a non-zero value

    // Initialize the rtcm3_t structure
    struct rtcm3_t rtcm3;
    rtcm3.dummy = 1; // Initialize with a non-zero value

    // Ensure the data is not NULL and has a reasonable size
    if (size == 0) {
        return 0;
    }

    // Call the function under test
    rtcm3_unpack(&context, &rtcm3, data);

    return 0;
}