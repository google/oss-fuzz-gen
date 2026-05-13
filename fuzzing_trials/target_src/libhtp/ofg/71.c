#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Initialize the htp_tx_t structure
    htp_tx_t tx;
    memset(&tx, 0, sizeof(htp_tx_t));

    // Ensure that the structure is not NULL
    if (size > 0) {
        // Assign some non-NULL values to the fields of htp_tx_t
        tx.request_method = (char *)data;
        tx.request_uri = (char *)data;
        tx.request_protocol = (char *)data;
    }

    // Call the function-under-test
    int result = htp_tx_get_is_config_shared(&tx);

    // Return 0 to indicate the fuzzer should continue testing
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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
