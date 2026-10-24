#include <stdint.h>
#include <stddef.h>
#include <ucl.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    // Ensure size is large enough to split into two strings
    if (size < 2) {
        return 0;
    }

    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Split the data into two parts for variable name and value
    size_t mid = size / 2;
    char *var_name = (char *)malloc(mid + 1);
    char *var_value = (char *)malloc(size - mid + 1);

    if (var_name == NULL || var_value == NULL) {
        ucl_parser_free(parser);
        free(var_name);
        free(var_value);
        return 0;
    }

    // Copy data into the variable name and value
    memcpy(var_name, data, mid);
    var_name[mid] = '\0';
    memcpy(var_value, data + mid, size - mid);
    var_value[size - mid] = '\0';

    // Call the function-under-test
    ucl_parser_register_variable(parser, var_name, var_value);

    // Clean up
    ucl_parser_free(parser);
    free(var_name);
    free(var_value);

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

    LLVMFuzzerTestOneInput_221(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
