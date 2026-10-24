#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include for memset
#include "gpsd_config.h"  // Include the configuration header
#include "gpsd.h"  // Include the header file where rtcm3_unpack is declared

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize the structures required for the function call
    struct gps_context_t context;
    struct rtcm3_t rtcm3;

    // Ensure the data is not null and has a minimum size
    if (size < 1) {
        return 0;
    }

    // Initialize the context structure to zero
    memset(&context, 0, sizeof(context));

    // Call the function-under-test
    rtcm3_unpack(&context, &rtcm3, data);

    return 0;
}

#ifdef __cplusplus
}
#endif