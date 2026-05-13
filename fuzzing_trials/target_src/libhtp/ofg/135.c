#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h"

// Function prototype for the fuzzer
int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Initialize htp_tx_t and htp_param_t structures
    htp_tx_t tx;
    htp_param_t param;

    // Ensure the data size is sufficient to fill the structures
    if (size < sizeof(htp_param_t)) {
        return 0;
    }

    // Initialize htp_param_t with data
    memset(&param, 0, sizeof(htp_param_t));

    // Allocate memory for name and value using bstr
    bstr *name_bstr = malloc(sizeof(bstr));
    bstr *value_bstr = malloc(sizeof(bstr));
    
    if (name_bstr == NULL || value_bstr == NULL) {
        free(name_bstr);
        free(value_bstr);
        return 0;
    }

    // Set up the name bstr
    name_bstr->len = size / 2;
    name_bstr->size = name_bstr->len;
    name_bstr->realptr = (unsigned char *)malloc(name_bstr->len);
    if (name_bstr->realptr == NULL) {
        free(name_bstr);
        free(value_bstr);
        return 0;
    }
    memcpy(name_bstr->realptr, data, name_bstr->len);

    // Set up the value bstr
    value_bstr->len = size - name_bstr->len;
    value_bstr->size = value_bstr->len;
    value_bstr->realptr = (unsigned char *)malloc(value_bstr->len);
    if (value_bstr->realptr == NULL) {
        free(name_bstr->realptr);
        free(name_bstr);
        free(value_bstr);
        return 0;
    }
    memcpy(value_bstr->realptr, data + name_bstr->len, value_bstr->len);

    // Assign bstr to param
    param.name = name_bstr;
    param.value = value_bstr;

    // Initialize htp_tx_t
    memset(&tx, 0, sizeof(htp_tx_t));

    // Call the function-under-test
    htp_status_t status = htp_tx_req_add_param(&tx, &param);

    // Free allocated memory
    free(name_bstr->realptr);
    free(name_bstr);
    free(value_bstr->realptr);
    free(value_bstr);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
