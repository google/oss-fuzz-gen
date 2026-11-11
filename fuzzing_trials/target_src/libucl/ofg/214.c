#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    const char *macro_name;
    ucl_macro_handler handler;
    void *user_data;

    // Initialize the parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (parser == NULL) {
        return 0;
    }

    // Ensure size is sufficient for a non-empty macro name
    if (size < 2) {
        ucl_parser_free(parser);
        return 0;
    }

    // Use the first byte of data as the macro name
    macro_name = (const char *)data;

    // Use the second byte of data to determine the handler
    handler = (ucl_macro_handler)(uintptr_t)data[1];

    // Use the rest of the data as user_data
    user_data = (void *)(data + 2);

    // Register the macro with the parser
    ucl_parser_register_macro(parser, macro_name, handler, user_data);

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

    LLVMFuzzerTestOneInput_214(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
