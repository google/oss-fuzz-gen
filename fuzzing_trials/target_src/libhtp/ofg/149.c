#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h> // Include for struct timeval

// Correct path for htp.h
#include "/src/libhtp/htp/htp.h"

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    // Create a configuration object needed for htp_connp_create
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0;
    }

    // Initialize htp_connp_t structure with the configuration
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    // Initialize htp_time_t structure using struct timeval
    struct timeval current_time;
    current_time.tv_sec = 0;
    current_time.tv_usec = 0;

    // Ensure data is not NULL and has a positive size
    if (data == NULL || size == 0) {
        htp_connp_destroy(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    // Call the function-under-test
    int result = htp_connp_req_data(connp, &current_time, data, size);

    // Clean up
    htp_connp_destroy(connp);
    htp_config_destroy(cfg);

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

    LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
