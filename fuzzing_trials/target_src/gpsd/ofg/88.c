#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <gps.h>  // Assuming the gps.h header provides the definition for struct gps_data_t

// Declare the function to avoid implicit declaration warnings
void gpsd_zero_satellites(struct gps_data_t *gps_data);

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Initialize a gps_data_t structure
    struct gps_data_t gps_data;

    // Ensure the gps_data structure is not NULL and is initialized
    // This is a basic initialization, you might need to adjust it based on the actual definition of gps_data_t
    gps_data.satellites_visible = 0;
    gps_data.satellites_used = 0;

    // Initialize the skyview array to NULL or appropriate values
    for (int i = 0; i < MAXCHANNELS; i++) {
        gps_data.skyview[i].ss = 0.0;
        gps_data.skyview[i].PRN = 0;
        gps_data.skyview[i].elevation = 0.0;
        gps_data.skyview[i].azimuth = 0.0;
        gps_data.skyview[i].used = false;
    }

    // If the input data is large enough, use it to initialize gps_data fields
    if (size >= sizeof(int) * 2) {
        gps_data.satellites_visible = data[0];
        gps_data.satellites_used = data[1];
    }

    // Call the function-under-test
    gpsd_zero_satellites(&gps_data);

    return 0;
}