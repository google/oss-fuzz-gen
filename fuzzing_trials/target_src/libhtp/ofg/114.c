#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h" // Correct path for the htp.h file

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to split into parts
    if (size < 2) {
        return 0;
    }

    // Initialize htp_tx_t object
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0;
    }

    // Use part of the data as the method string
    size_t method_len = size / 2;
    char *method = (char *)malloc(method_len + 1);
    if (method == NULL) {
        free(tx);
        return 0;
    }
    memcpy(method, data, method_len);
    method[method_len] = '\0'; // Null-terminate the string

    // Use the remaining part of the data to determine the allocation strategy
    enum htp_alloc_strategy_t alloc_strategy = (enum htp_alloc_strategy_t)data[method_len];

    // Call the function-under-test
    htp_status_t status = htp_tx_req_set_method(tx, method, method_len, alloc_strategy);

    // Clean up
    free(tx);
    free(method);

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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
