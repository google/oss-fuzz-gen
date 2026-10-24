#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assume these structures are defined in the relevant header files.
struct gps_device_t {
    int dummy;  // Placeholder for actual structure members.
};

struct timedelta_t {
    int dummy;  // Placeholder for actual structure members.
};

// Assume the function is declared in the relevant header file.
void ntp_latch(struct gps_device_t *gps, struct timedelta_t *td);

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize gps_device_t
    struct gps_device_t gps;
    memset(&gps, 0, sizeof(gps));

    // Initialize timedelta_t
    struct timedelta_t td;
    memset(&td, 0, sizeof(td));

    // Use the input data to modify the structures
    if (size > 0) {
        size_t gps_size = sizeof(gps);
        size_t td_size = sizeof(td);

        // Copy data into gps structure
        size_t copy_size = size < gps_size ? size : gps_size;
        memcpy(&gps, data, copy_size);

        // If there's more data, copy it into the td structure
        if (size > gps_size) {
            copy_size = size - gps_size < td_size ? size - gps_size : td_size;
            memcpy(&td, data + gps_size, copy_size);
        }
    }

    // Call the function-under-test
    ntp_latch(&gps, &td);

    return 0;
}