#include <stdint.h>
#include <stdlib.h>
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    htp_tx_t *tx = htp_tx_create(NULL);
    if (tx == NULL) {
        return 0;
    }

    // Ensure the data pointer is not NULL and size is non-zero
    if (data != NULL && size > 0) {
        // Call the function-under-test
        htp_status_t status = htp_tx_req_process_body_data(tx, (const void *)data, size);

        // Handle the status if needed (for fuzzing, we generally don't need to)
        // For example, you might log or assert based on the status
    }

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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
