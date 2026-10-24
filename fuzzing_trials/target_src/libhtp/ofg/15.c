#include <stdint.h>
#include <stddef.h>
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize the transaction object
    htp_tx_t *tx = htp_tx_create(NULL);
    if (tx == NULL) {
        return 0; // If creation fails, exit early
    }

    // Ensure the data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Call the function-under-test
        htp_status_t status = htp_tx_res_process_body_data(tx, data, size);

        // You can add additional checks or logging based on the status if needed
    }

    // Clean up the transaction object
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
