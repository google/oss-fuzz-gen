#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ucl.h"  // Assuming the ucl.h header file contains the declaration for ucl_parser_add_string_priority

int LLVMFuzzerTestOneInput_209(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;
    const char *string;
    unsigned int priority;

    // Initialize the parser
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (parser == NULL) {
        return 0;
    }

    // Ensure the data is null-terminated for string operations
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        ucl_parser_free(parser);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Set the string to the null-terminated data
    string = null_terminated_data;

    // Use a fixed priority for fuzzing
    priority = 1;

    // Call the function-under-test
    ucl_parser_add_string_priority(parser, string, size, priority);

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

    LLVMFuzzerTestOneInput_209(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
