#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_206(const uint8_t *data, size_t size) {
    // Initialize the ucl_parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Define non-NULL values for the parameters
    unsigned int priority = 0; // Example priority value
    enum ucl_duplicate_strategy dup_strategy = UCL_DUPLICATE_APPEND; // Example strategy
    enum ucl_parse_type parse_type = UCL_PARSE_UCL; // Example parse type

    // Call the function-under-test
    bool result = ucl_parser_add_chunk_full(parser, data, size, priority, dup_strategy, parse_type);

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

    LLVMFuzzerTestOneInput_206(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
