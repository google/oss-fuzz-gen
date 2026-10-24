#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a ucl_object_t
    if (size < 1) {
        return 0;
    }

    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data into a UCL object
    ucl_parser_add_chunk(parser, data, size);
    const ucl_object_t *obj = ucl_parser_get_object(parser);
    if (obj == NULL) {
        ucl_parser_free(parser);
        return 0;
    }

    // Prepare a boolean variable to store the result
    _Bool result;

    // Call the function-under-test
    ucl_object_toboolean_safe(obj, &result);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
