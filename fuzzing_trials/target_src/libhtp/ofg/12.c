#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Allocate memory for htp_tx_t structure
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0;
    }

    // Initialize the structure with some non-NULL values
    // Ensure the data is null-terminated before using as a string
    char *request_method = (char *)malloc(size + 1);
    char *request_uri = (char *)malloc(size + 1);
    if (request_method == NULL || request_uri == NULL) {
        free(tx);
        free(request_method);
        free(request_uri);
        return 0;
    }

    memcpy(request_method, data, size);
    memcpy(request_uri, data, size);
    request_method[size] = '\0';
    request_uri[size] = '\0';

    tx->request_method = request_method;
    tx->request_uri = request_uri;

    // Call the function under test
    htp_status_t status = htp_tx_destroy(tx);

    // Free the allocated memory
    free(request_method);
    free(request_uri);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
