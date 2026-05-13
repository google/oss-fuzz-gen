#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htp/htp.h>

// Function signature for the fuzzer
int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for a parameter name
    if (size < 2) {
        return 0;
    }

    // Allocate and initialize a dummy htp_tx_t object
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0;
    }
    memset(tx, 0, sizeof(htp_tx_t));

    // Use part of the data as the parameter name
    size_t param_name_length = size - 1;
    char *param_name = (char *)malloc(param_name_length + 1);
    if (param_name == NULL) {
        free(tx);
        return 0;
    }
    memcpy(param_name, data, param_name_length);
    param_name[param_name_length] = '\0';

    // Call the function-under-test
    htp_param_t *param = htp_tx_req_get_param(tx, param_name, param_name_length);

    // Clean up
    free(param_name);
    free(tx);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
