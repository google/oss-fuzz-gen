#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    struct lyxp_var *vars = NULL;
    const char *var_name = "test_var";
    char *var_value;

    // Ensure we have enough data to create a non-empty string
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the variable value and copy the data into it
    var_value = (char *)malloc(size + 1);
    if (var_value == NULL) {
        return 0;
    }
    memcpy(var_value, data, size);
    var_value[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    lyxp_vars_set(&vars, var_name, var_value);

    // Clean up
    free(var_value);
    lyxp_vars_free(vars);

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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
