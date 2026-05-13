#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <htp/htp.h>
#include <htp/htp_config_auto.h>
#include <htp/htp_connection_parser.h> // Include the header where htp_connp_create is declared
#include <htp/htp_transaction.h> // Include the header where htp_tx_create is declared

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Declare and initialize the necessary variables
    htp_connp_t *connp = NULL;
    htp_tx_t *tx = NULL;
    htp_cfg_t *cfg = htp_config_create(); // Create a configuration object

    if (cfg == NULL) {
        return 0; // Exit if configuration creation fails
    }

    // Create the htp_connp_t structure using the library function
    connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg); // Clean up the configuration object
        return 0; // Exit if creation fails
    }

    // Call the function-under-test
    tx = htp_tx_create(connp);

    // Clean up
    if (tx != NULL) {
        // Assuming there's a function to destroy or free htp_tx_t
        // htp_tx_destroy(tx); // Uncomment if such a function exists
    }

    htp_connp_destroy_all(connp);
    htp_config_destroy(cfg); // Clean up the configuration object

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
