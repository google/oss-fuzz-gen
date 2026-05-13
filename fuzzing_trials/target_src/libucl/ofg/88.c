#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Initialize the UCL parser
    struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    // Parse the input data
    if (parser != NULL && size > 0) {
        ucl_parser_add_chunk(parser, data, size);

        // Get the root object
        const ucl_object_t *root = ucl_parser_get_object(parser);
        
        if (root != NULL) {
            // Create an iterator
            ucl_object_iter_t iter = ucl_object_iterate_new(root);

            // Call the function-under-test
            ucl_object_iterate_free(iter);

            // Free the root object
            ucl_object_unref(root);
        }

        // Free the parser
        ucl_parser_free(parser);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
