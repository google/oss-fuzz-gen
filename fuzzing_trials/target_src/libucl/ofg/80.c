#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    const char *error;

    // Initialize the UCL parser
    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    if (parser != NULL) {
        // Simulate parsing input data
        ucl_parser_add_chunk(parser, data, size);

        // Call the function-under-test
        error = ucl_parser_get_error(parser);

        // Normally, you would do something with the error string here,
        // but for fuzzing, we just ensure the function is called.

        // Clean up the parser
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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
