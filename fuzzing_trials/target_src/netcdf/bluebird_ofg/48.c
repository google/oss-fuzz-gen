#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc_get_var_string(int var1, int var2, char **var3);

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers and a string
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract two integers from the input data
    int var1 = *(const int *)data;
    int var2 = *(const int *)(data + sizeof(int));

    // Calculate the remaining size for the string
    size_t string_size = size - sizeof(int) * 2;

    // Allocate memory for the string and ensure it's null-terminated
    char *var3 = (char *)malloc(string_size + 1);
    if (var3 == NULL) {
        return 0;
    }
    memcpy(var3, data + sizeof(int) * 2, string_size);
    var3[string_size] = '\0';

    // Call the function-under-test
    nc_get_var_string(var1, var2, &var3);

    // Free allocated memory
    free(var3);

    return 0;
}