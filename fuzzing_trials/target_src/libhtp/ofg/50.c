#include <stdint.h>
#include <stddef.h>
#include <htp/htp.h>

// Include the necessary header for htp_alloc_strategy_t
#include <htp/htp_private.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a non-empty string and enumeration
    if (size < 2) {
        return 0;
    }

    // Create a transaction object
    htp_tx_t *tx = htp_tx_create(NULL);
    if (tx == NULL) {
        return 0;
    }

    // Use the first byte of data to determine the allocation strategy
    enum htp_alloc_strategy_t alloc_strategy = (enum htp_alloc_strategy_t)(data[0] % 2);

    // Use the remaining data as the request line string
    const char *req_line = (const char *)(data + 1);
    size_t req_line_len = size - 1;

    // Call the function-under-test
    htp_status_t status = htp_tx_req_set_line(tx, req_line, req_line_len, alloc_strategy);

    // Clean up
    htp_tx_destroy(tx);

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
