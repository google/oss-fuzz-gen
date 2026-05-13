#include <stdint.h>
#include <stdlib.h>
#include <htp/htp.h>
#include <htp/htp_config.h>
#include <htp/htp_connection_parser.h>
#include "/src/libhtp/htp/htp_core.h" // Corrected include path

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Create a configuration object
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0;
    }

    // Create a connection parser with the configuration
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    // Simulate some data processing with a timestamp
    htp_time_t timestamp = {0}; // Initialize timestamp to zero or appropriate value
    htp_connp_res_data(connp, &timestamp, data, size);

    // Call the function-under-test
    size_t consumed = htp_connp_res_data_consumed(connp);

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
