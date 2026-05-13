#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h" // Correct path to the header file

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    htp_tx_t tx;
    const char *method;
    size_t method_len;
    enum htp_alloc_strategy_t alloc_strategy; // Use 'enum' to declare the type

    // Ensure the size is sufficient for extracting method and alloc_strategy
    if (size < sizeof(enum htp_alloc_strategy_t) + 1) {
        return 0;
    }

    // Allocate memory for the method string
    method_len = size - sizeof(enum htp_alloc_strategy_t);
    method = (const char *)malloc(method_len + 1);
    if (method == NULL) {
        return 0;
    }

    // Copy method from data
    memcpy((char *)method, data, method_len);
    ((char *)method)[method_len] = '\0'; // Null-terminate the string

    // Extract alloc_strategy from the end of the data
    alloc_strategy = *(enum htp_alloc_strategy_t *)(data + method_len);

    // Call the function-under-test
    htp_status_t status = htp_tx_req_set_method(&tx, method, method_len, alloc_strategy);

    // Clean up
    free((void *)method);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
