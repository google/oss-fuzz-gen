#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    ucl_object_t *obj;
    struct ucl_parser *parser;

    // Initialize the parser
    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    // Parse the input data
    if (ucl_parser_add_chunk(parser, data, size)) {
        // Get the parsed object
        obj = ucl_parser_get_object(parser);
        if (obj != NULL) {
            // Call the function-under-test
            double result = ucl_object_todouble(obj);

            // Use the result in some way to prevent optimization
            volatile double prevent_optimization = result;
            (void)prevent_optimization;

            // Free the object
            ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
