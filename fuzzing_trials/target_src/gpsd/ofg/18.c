#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming gps_device_t is defined somewhere in the included headers
struct gps_device_t {
    // Mock fields for demonstration purposes
    double speed;
    double latitude;
    double longitude;
};

// Mock function definition for gpsd_get_speed_old_18
int gpsd_get_speed_old_18(const struct gps_device_t *device) {
    // Placeholder implementation, replace with actual logic
    if (device != NULL) {
        return (int)(device->speed);
    }
    return -1;
}

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    if (size < sizeof(struct gps_device_t)) {
        return 0;
    }

    struct gps_device_t device;
    // Ensure the data size is suitable to fill the gps_device_t structure
    memcpy(&device, data, sizeof(struct gps_device_t));

    // Call the function under test
    int speed = gpsd_get_speed_old_18(&device);

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile int result = speed;
    (void)result;

    // Additional logic to use the other fields in the struct
    // This helps to increase code coverage by ensuring the fuzz target
    // exercises more code paths.
    if (device.latitude != 0.0 || device.longitude != 0.0) {
        // Mock additional processing that might affect the function's behavior
        // This is just to simulate usage of the other fields
        double combined = device.latitude + device.longitude;
        if (combined > 180.0) {
            result = -result; // Arbitrary operation to simulate some logic
        }
    }

    return 0;
}