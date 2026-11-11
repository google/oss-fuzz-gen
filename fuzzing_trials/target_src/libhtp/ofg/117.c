#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h" // Correct path to the header where htp_tx_res_set_header is declared

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Initialize the required variables
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0; // Exit if memory allocation fails
    }
    
    // Ensure data size is sufficient for splitting into two strings
    if (size < 2) {
        free(tx);
        return 0;
    }

    // Split data into two parts for header name and value
    size_t name_len = size / 2;
    size_t value_len = size - name_len;

    char *header_name = (char *)malloc(name_len + 1);
    char *header_value = (char *)malloc(value_len + 1);

    if (header_name == NULL || header_value == NULL) {
        free(tx);
        free(header_name);
        free(header_value);
        return 0;
    }

    // Copy data into header name and value, ensuring null-termination
    memcpy(header_name, data, name_len);
    header_name[name_len] = '\0';

    memcpy(header_value, data + name_len, value_len);
    header_value[value_len] = '\0';

    // Choose an allocation strategy (using the correct enum value)
    enum htp_alloc_strategy_t alloc_strategy = HTP_ALLOC_REUSE;

    // Call the function-under-test
    htp_status_t status = htp_tx_res_set_header(tx, header_name, name_len, header_value, value_len, alloc_strategy);

    // Clean up
    free(tx);
    free(header_name);
    free(header_value);

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

    LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
