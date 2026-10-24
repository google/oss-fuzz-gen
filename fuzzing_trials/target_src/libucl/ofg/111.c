#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);

    if (parser == NULL) {
        return 0;
    }

    // Try to parse the input data
    if (!ucl_parser_add_chunk(parser, data, size)) {
        ucl_parser_free(parser);
        return 0;
    }

    // Get the UCL object
    const ucl_object_t *obj = ucl_parser_get_object(parser);

    if (obj != NULL) {
        // Prepare a size variable
        size_t len = 0;

        // Call the function-under-test
        const char *str = ucl_object_tolstring(obj, &len);

        // Use the result in some way to avoid compiler optimizations
        if (str != NULL) {
            // Do something with str and len, e.g., print or log
            // For this example, we'll just ensure the variables are used
            (void)str;
            (void)len;
        }

        // Free the UCL object
        ucl_object_unref(obj);
    }

    // Free the parser
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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
