#include <stdint.h>
#include <stdlib.h>
#include <htp/htp.h>

// Function signature for fuzzing input
int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize htp_tx_t object
    htp_tx_t *tx = htp_tx_create(NULL);
    if (tx == NULL) {
        return 0;
    }

    // Extract an integer from the input data
    int status_code = *((int *)data);

    // Call the function-under-test
    htp_tx_res_set_status_code(tx, status_code);

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

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
