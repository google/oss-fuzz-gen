#include <stdint.h>
#include <stddef.h>
#include "/src/libhtp/htp/htp.h" // Correct path to the header file

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize the htp_tx_t structure
    htp_tx_t tx;
    // Assuming htp_tx_t has a function or method to initialize, if not, directly use it

    // Extract an integer from the data
    int protocol_version = *((int *)data);

    // Call the function-under-test
    htp_tx_req_set_protocol_0_9(&tx, protocol_version);

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

    LLVMFuzzerTestOneInput_157(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
