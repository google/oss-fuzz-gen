#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Initialize a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    ucl_object_t *root_obj = NULL;
    ucl_object_t *popped_obj = NULL;

    // Check if the parser was successfully created
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    if (ucl_parser_add_chunk(parser, data, size)) {
        // Get the root object from the parser
        root_obj = ucl_parser_get_object(parser);

        // Ensure the root object is an array for the test case
        if (root_obj != NULL && ucl_object_type(root_obj) == UCL_ARRAY) {
            // Call the function-under-test
            popped_obj = ucl_array_pop_last(root_obj);

            // Clean up the popped object
            if (popped_obj != NULL) {
                ucl_object_unref(popped_obj);
            }
        }

        // Clean up the root object
        if (root_obj != NULL) {
            ucl_object_unref(root_obj);
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
