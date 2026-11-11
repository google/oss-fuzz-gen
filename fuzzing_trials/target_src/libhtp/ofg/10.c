#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the appropriate header for htp_tx_t
#include "/src/libhtp/htp/htp.h"

// Remove 'extern "C"' as it is not valid in C, it's a C++ construct
int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid htp_tx_t structure
    if (size < sizeof(htp_tx_t)) {
        return 0;
    }

    // Allocate memory for htp_tx_t and initialize it with fuzz data
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0;
    }

    // Copy data into the htp_tx_t structure
    memcpy(tx, data, sizeof(htp_tx_t));

    // Call the function under test
    int result = htp_tx_req_has_body(tx);

    // Free allocated memory
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
