#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_210(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    const char *input_string;
    unsigned int priority;

    // Initialize the parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Ensure input string is null-terminated
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        ucl_parser_free(parser);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    input_string = (const char *)null_terminated_data;
    priority = 0; // Try different priority values if needed

    // Call the function-under-test
    ucl_parser_add_string_priority(parser, input_string, size, priority);

    // Clean up
    free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_210(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
