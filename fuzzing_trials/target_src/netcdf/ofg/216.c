#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function nc_get_var_text is defined elsewhere
extern int nc_get_var_text(int ncid, int varid, char *text);

int LLVMFuzzerTestOneInput_216(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract two integers and a string
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract the first integer (ncid) from the data
    int ncid = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer (varid) from the data
    int varid = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for the text, ensuring it is null-terminated
    char *text = (char *)malloc(size + 1);
    if (text == NULL) {
        return 0;
    }
    memcpy(text, data, size);
    text[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    nc_get_var_text(ncid, varid, text);

    // Free allocated memory
    free(text);

    return 0;
}