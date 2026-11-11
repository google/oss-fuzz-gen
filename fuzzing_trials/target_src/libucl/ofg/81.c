#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    const char *error_msg;

    // Initialize the UCL parser
    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    // Check if parser was created successfully
    if (parser == NULL) {
        return 0; // Exit if parser creation failed
    }

    // Try to parse the input data
    ucl_parser_add_chunk(parser, data, size);

    // Retrieve any error message from the parser
    error_msg = ucl_parser_get_error(parser);

    // Perform any necessary operations with the error message
    // For fuzzing purposes, we just ensure the function is called

    // Clean up and free the parser
    ucl_parser_free(parser);

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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
