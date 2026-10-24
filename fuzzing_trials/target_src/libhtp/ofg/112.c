#include <stdint.h>
#include <stdlib.h>
#include <htp/htp.h>
#include <htp/htp_config.h>
#include <htp/htp_transaction.h>
#include "/src/libhtp/htp/htp_connection_parser_private.h"

// Function prototype for the fuzzing entry point
int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Initialize the HTP configuration
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0;
    }

    // Initialize the HTP connection
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    // Ensure the data is not empty
    if (size == 0) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    // Feed the input data to the connection parser
    htp_status_t status = htp_connp_req_data(connp, NULL, data, size);

    // Check the status to ensure the function was invoked properly
    if (status != HTP_OK && status != HTP_DATA) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    // Additional processing can be added here if needed

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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
