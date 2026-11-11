#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Fuzzer harness for ucl_parser_get_linenum
int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;

    // Initialize the UCL parser
    parser = ucl_parser_new(0);

    // Ensure the parser is not NULL
    if (parser == NULL) {
        return 0;
    }

    // Feed the data to the parser
    if (size > 0) {
        ucl_parser_add_chunk(parser, data, size);
    }

    // Call the function-under-test
    unsigned int linenum = ucl_parser_get_linenum(parser);

    // Clean up
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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
