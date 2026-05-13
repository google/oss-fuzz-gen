#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

// Dummy variable handler function for fuzzing
static const char* dummy_variable_handler(const char *var_name, size_t var_len, void *ud) {
    return "dummy_value";
}

int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    void *user_data = (void*)data; // Use data as user data

    // Initialize the parser
    parser = ucl_parser_new(0);

    if (parser != NULL) {
        // Set the variables handler
        ucl_parser_set_variables_handler(parser, dummy_variable_handler, user_data);

        // Cleanup
        ucl_parser_free(parser);
    }

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

    LLVMFuzzerTestOneInput_186(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
