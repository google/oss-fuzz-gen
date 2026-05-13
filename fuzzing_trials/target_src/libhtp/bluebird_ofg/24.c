#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "htp/htp.h"
#include <sys/time.h> // Include the correct header for struct timeval
#include <string.h>   // Include for memcpy

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Initialize the configuration for htp_connp_create
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0; // Exit if the configuration creation fails
    }

    // Create a connection parser with the configuration
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg); // Clean up configuration
        return 0; // Exit if the connection parser creation fails
    }

    struct timeval time; // Use struct timeval instead of htp_time_t
    if (size >= sizeof(struct timeval)) {
        // Use the data to initialize struct timeval if there is enough data
        memcpy(&time, data, sizeof(struct timeval));
    } else {
        // Otherwise, set some default non-NULL values
        time.tv_sec = 1;
        time.tv_usec = 1000; // Use a default microsecond value
    }

    // Call the function-under-test
    htp_connp_req_close(connp, &time);

    // Clean up
    htp_connp_destroy_all(connp);
    htp_config_destroy(cfg); // Clean up configuration

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
