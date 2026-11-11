#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h"

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Allocate and initialize htp_tx_t and htp_uri_t structures
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    htp_uri_t *uri = (htp_uri_t *)malloc(sizeof(htp_uri_t));

    if (tx == NULL || uri == NULL) {
        // If allocation fails, free and return
        free(tx);
        free(uri);
        return 0;
    }

    // Zero out the structures to ensure all fields are initialized
    memset(tx, 0, sizeof(htp_tx_t));
    memset(uri, 0, sizeof(htp_uri_t));

    // Initialize the structures with non-NULL values
    tx->request_method = strdup("GET");
    tx->request_uri = strdup("/example");

    uri->scheme = strdup("http");
    uri->hostname = strdup("example.com");
    uri->port = 80;
    uri->path = strdup("/path");
    uri->query = strdup("query=1");

    // Call the function-under-test
    htp_tx_req_set_parsed_uri(tx, uri);

    // Clean up
    free(tx->request_method);
    free(tx->request_uri);
    free(uri->scheme);
    free(uri->hostname);
    free(uri->path);
    free(uri->query);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
