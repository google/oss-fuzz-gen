#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

// Assuming DW_TAG_enumeration_typeucl_duplicate_strategy and DW_TAG_enumeration_typeucl_parse_type are enums
typedef enum {
    UCL_DUPLICATE_STRATEGY_1,
    UCL_DUPLICATE_STRATEGY_2,
    // Add other strategies as needed
} DW_TAG_enumeration_typeucl_duplicate_strategy;

typedef enum {
    UCL_PARSE_TYPE_1,
    UCL_PARSE_TYPE_2,
    // Add other parse types as needed
} DW_TAG_enumeration_typeucl_parse_type;

int LLVMFuzzerTestOneInput_205(const uint8_t *data, size_t size) {
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    unsigned int priority = 0; // Example priority, can be varied
    DW_TAG_enumeration_typeucl_duplicate_strategy dup_strategy = UCL_DUPLICATE_STRATEGY_1;
    DW_TAG_enumeration_typeucl_parse_type parse_type = UCL_PARSE_TYPE_1;

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

    LLVMFuzzerTestOneInput_205(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
