#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize both structures
    if (size < sizeof(htp_tx_t) + sizeof(htp_uri_t)) {
        return 0;
    }

    // Allocate memory for htp_tx_t and htp_uri_t
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    htp_uri_t *uri = (htp_uri_t *)malloc(sizeof(htp_uri_t));

    if (tx == NULL || uri == NULL) {
        free(tx);
        free(uri);
        return 0;
    }

    // Initialize htp_tx_t and htp_uri_t with the provided data
    // Note: This is a simplistic initialization, actual initialization
    // may require setting specific fields based on the library's requirements
    memcpy(tx, data, sizeof(htp_tx_t));
    memcpy(uri, data + sizeof(htp_tx_t), sizeof(htp_uri_t));

    // Call the function under test
    htp_tx_req_set_parsed_uri(tx, uri);

    // Clean up
    free(tx);
    free(uri);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
