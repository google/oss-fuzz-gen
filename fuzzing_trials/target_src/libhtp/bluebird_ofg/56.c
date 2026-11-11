#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h"

// Function prototype for the fuzzing entry point
int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Initialize the htp_cfg_t structure
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0; // Exit if memory allocation failed
    }

    // Initialize the htp_connp_t structure
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0; // Exit if memory allocation failed
    }

    // Ensure the data pointer is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Call the function-under-test
        htp_status_t status = htp_connp_req_data(connp, NULL, data, size);
    }

    // Clean up
    htp_connp_destroy_all(connp);
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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
