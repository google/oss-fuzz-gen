#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h"

// Include the necessary header for the enum definition
#include "/src/libhtp/htp/htp_transaction.h"

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a valid URI and allocation strategy
    if (size < 2) {
        return 0;
    }

    // Allocate memory for htp_tx_t
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0;
    }

    // Create a URI string from the input data
    char *uri = (char *)malloc(size + 1);
    if (uri == NULL) {
        free(tx);
        return 0;
    }
    memcpy(uri, data, size);
    uri[size] = '\0'; // Null-terminate the URI string

    // Use the first byte of data to determine the allocation strategy
    enum htp_alloc_strategy_t alloc_strategy = (enum htp_alloc_strategy_t)(data[0] % 3);

    // Call the function-under-test
    htp_status_t status = htp_tx_req_set_uri(tx, uri, size, alloc_strategy);

    // Clean up
    free(uri);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
