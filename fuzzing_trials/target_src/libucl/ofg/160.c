#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

// Dummy handler function for ucl_context_macro_handler
bool dummy_macro_handler_160(struct ucl_parser *parser, const char *macro, void *ud) {
    return true;
}

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize ucl_parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Use data as a string for the macro name
    char *macro_name = (char *)malloc(size + 1);
    if (macro_name == NULL) {
        ucl_parser_free(parser);
        return 0;
    }
    memcpy(macro_name, data, size);
    macro_name[size] = '\0';

    // Use a non-NULL pointer for the user data
    void *user_data = (void *)0x1;

    // Call the function-under-test
    ucl_parser_register_context_macro(parser, macro_name, dummy_macro_handler_160, user_data);

    // Clean up
    free(macro_name);
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

    LLVMFuzzerTestOneInput_160(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
