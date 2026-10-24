#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Initialize UCL parser
    struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
    ucl_object_t *obj = NULL;

    // Check if parser is created successfully
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    if (ucl_parser_add_chunk(parser, data, size)) {
        // Get the UCL object
        obj = ucl_parser_get_object(parser);

        // Ensure the object is an array
        if (obj != NULL && ucl_object_type(obj) == UCL_ARRAY) {
            // Call the function-under-test
            ucl_object_t *popped_obj = ucl_array_pop_last(obj);

            // Free the popped object if it exists
            if (popped_obj != NULL) {
                ucl_object_unref(popped_obj);
            }
        }

        // Free the UCL object
        if (obj != NULL) {
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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
