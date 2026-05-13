#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h"  // Correct path for htp.h
#include "/src/libhtp/htp/htp_transaction.h"  // Include header for htp_tx_create function
#include "/src/libhtp/htp/htp_connection_parser.h"  // Include header for htp_connp_t

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the string and other parameters
    if (size < 4) {
        return 0;
    }

    // Create a connection parser object
    htp_connp_t *connp = htp_connp_create(NULL);
    if (connp == NULL) {
        return 0;
    }

    // Initialize htp_tx_t object
    htp_tx_t *tx = htp_tx_create(connp);
    if (tx == NULL) {
        htp_connp_destroy_all(connp);
        return 0;
    }

    // Extract htp_data_source_t from data
    enum htp_data_source_t data_source = (enum htp_data_source_t)data[0];

    // Prepare a string from the data
    size_t str_len = size - 1;
    char *param_name = (char *)malloc(str_len + 1);
    if (param_name == NULL) {
        htp_tx_destroy(tx);
        htp_connp_destroy_all(connp);
        return 0;
    }
    memcpy(param_name, data + 1, str_len);
    param_name[str_len] = '\0';

    // Call the function-under-test
    htp_param_t *param = htp_tx_req_get_param_ex(tx, data_source, param_name, str_len);

    // Clean up
    free(param_name);
    htp_tx_destroy(tx);
    htp_connp_destroy_all(connp);

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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
