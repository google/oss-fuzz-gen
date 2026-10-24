#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ucl.h>
#include <stdlib.h> // Include for malloc and free

bool dummy_macro_handler_159(struct ucl_parser *parser, const char *macro, void *ud) {
    // Dummy handler function for testing
    return true;
}

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    const char *macro_name;
    void *user_data = (void *)0x1; // Non-NULL user data

    // Initialize the parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (parser == NULL) {
        return 0;
    }

    // Ensure the data is null-terminated for the macro name
    char *macro_buffer = (char *)malloc(size + 1);
    if (macro_buffer == NULL) {
        ucl_parser_free(parser);
        return 0;
    }
    memcpy(macro_buffer, data, size);
    macro_buffer[size] = '\0';

    macro_name = macro_buffer;

    // Call the function-under-test
    ucl_parser_register_context_macro(parser, macro_name, dummy_macro_handler_159, user_data);

    // Clean up
    free(macro_buffer);
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

    LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
