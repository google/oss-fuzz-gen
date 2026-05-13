#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Define a comparison function for sorting
int compare_ucl_objects(const ucl_object_t **a, const ucl_object_t **b) {
    // Compare the two objects based on their keys
    return ucl_object_compare(*a, *b);
}

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    ucl_object_t *ucl_array;
    struct ucl_parser *parser;
    int (*compare_func)(const ucl_object_t **, const ucl_object_t **) = compare_ucl_objects;

    // Initialize the UCL parser
    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    // Parse the input data
    if (ucl_parser_add_chunk(parser, data, size)) {
        // Get the root object
        ucl_array = ucl_parser_get_object(parser);

        // Check if the root object is an array
        if (ucl_array && ucl_object_type(ucl_array) == UCL_ARRAY) {
            // Sort the array using the comparison function
            ucl_object_array_sort(ucl_array, compare_func);
        }

        // Free the UCL object
        ucl_object_unref(ucl_array);
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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
