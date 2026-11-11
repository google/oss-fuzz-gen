#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <htp/htp.h>

// Define a dummy callback function to be used as a parameter
void dummy_callback_106(htp_tx_data_t *data) {
    // Implement a simple callback that does nothing
    (void)data; // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    htp_tx_t *tx = htp_tx_create(NULL);
    
    if (tx == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Call the function-under-test with non-NULL parameters
    htp_tx_register_request_body_data(tx, dummy_callback_106);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
