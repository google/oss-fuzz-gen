#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure there is enough data for both the attribute name and text
    if (size < 3) return 0; // Adjusted to ensure there's at least 1 byte for each part

    // Split the input data into two parts for the attribute name and text
    size_t name_len = data[0] % (size - 2) + 1; // Ensure name_len is at least 1
    size_t text_len = size - 1 - name_len;

    // Allocate memory for the attribute name and text
    char *att_name = (char *)malloc(name_len + 1);
    char *att_text = (char *)malloc(text_len + 1);

    if (att_name == NULL || att_text == NULL) {
        free(att_name);
        free(att_text);
        return 0;
    }

    // Copy data into the attribute name and text, ensuring null-termination
    memcpy(att_name, data + 1, name_len);
    att_name[name_len] = '\0';

    memcpy(att_text, data + 1 + name_len, text_len);
    att_text[text_len] = '\0';

    // Define some arbitrary non-zero IDs for ncid and varid
    int ncid = 1;
    int varid = 1;

    // Call the function-under-test
    nc_put_att_text(ncid, varid, att_name, text_len, att_text);

    // Free allocated memory
    free(att_name);
    free(att_text);

    return 0;
}