#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    unsigned int priority = 0;

    // Initialize the UCL parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);

    if (parser == NULL) {
        return 0;
    }

    // Ensure the data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Call the function-under-test
        ucl_parser_add_chunk_priority(parser, data, size, priority);
    }

    // Clean up the parser
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

    LLVMFuzzerTestOneInput_154(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
