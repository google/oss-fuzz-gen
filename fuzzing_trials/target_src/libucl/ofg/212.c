#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include "/src/libucl/include/ucl.h"

int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    // Initialize variables
    ucl_object_t *obj = NULL;
    const char *output_str = NULL;
    size_t output_size = 0;
    struct ucl_parser *parser;

    // Check if size is non-zero
    if (size == 0) {
        return 0;
    }

    // Create a new UCL parser
    parser = ucl_parser_new(0);

    // Parse the input data into a UCL object
    if (!ucl_parser_add_chunk(parser, data, size)) {
        ucl_parser_free(parser);
        return 0;
    }

    // Get the parsed UCL object
    obj = ucl_parser_get_object(parser);

    // Ensure the object is not NULL
    if (obj == NULL) {
        ucl_parser_free(parser);
        return 0;
    }

    // Call the function under test
    bool result = ucl_object_tolstring_safe(obj, &output_str, &output_size);

    // Clean up
    ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_212(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
