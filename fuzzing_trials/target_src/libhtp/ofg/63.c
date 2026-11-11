#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create an htp_tx_t object
    if (size < sizeof(htp_tx_t)) {
        return 0;
    }

    // Allocate memory for htp_tx_t
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0;
    }

    // Initialize the htp_tx_t object with data
    // Assuming the data is enough to fill htp_tx_t, otherwise, adjust accordingly
    memcpy(tx, data, sizeof(htp_tx_t));

    // Call the function-under-test
    void *user_data = htp_tx_get_user_data(tx);

    // Use the result (in this case, we are just discarding it)
    (void)user_data;

    // Free the allocated memory
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
