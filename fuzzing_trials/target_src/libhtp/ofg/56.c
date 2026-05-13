#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htp/htp.h>

// Ensure that the htp_data_source_t is correctly used as an enum
int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Initialize htp_tx_t structure
    htp_tx_t tx;
    memset(&tx, 0, sizeof(htp_tx_t));

    // Ensure the data is not empty and has a reasonable size
    if (size < 2) {
        return 0;
    }

    // Use the first byte of data to determine the htp_data_source_t value
    enum htp_data_source_t data_source = (enum htp_data_source_t)(data[0] % 2);

    // Use the rest of the data as the parameter name
    const char *param_name = (const char *)(data + 1);
    size_t param_name_size = size - 1;

    // Ensure the parameter name is null-terminated to prevent errors
    char *param_name_copy = (char *)malloc(param_name_size + 1);
    if (param_name_copy == NULL) {
        return 0;
    }
    memcpy(param_name_copy, param_name, param_name_size);
    param_name_copy[param_name_size] = '\0';

    // Call the function-under-test
    htp_param_t *param = htp_tx_req_get_param_ex(&tx, data_source, param_name_copy, param_name_size);

    // Optionally, handle the returned htp_param_t if necessary
    // For fuzzing purposes, we just ensure the function is called

    // Free the allocated memory
    free(param_name_copy);

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
