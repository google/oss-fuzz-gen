#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    ucl_object_t *ucl_obj;
    struct ucl_parser *parser;
    const char *result;

    // Initialize the UCL parser
    parser = ucl_parser_new(0);

    // Use the input data to parse a UCL object
    if (ucl_parser_add_chunk(parser, data, size)) {
        ucl_obj = ucl_parser_get_object(parser);
        if (ucl_obj != NULL) {
            // Call the function-under-test
            result = ucl_object_tostring(ucl_obj);

            // Normally, you would do something with the result here
            // For fuzzing, we're primarily interested in ensuring the function can handle the input

            // Free the UCL object
            ucl_object_unref(ucl_obj);
        }
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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
