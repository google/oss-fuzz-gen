#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Initialize the UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    ucl_object_t *root = NULL;
    ucl_object_t *element = NULL;

    // Ensure size is non-zero to avoid empty parse
    if (size > 0) {
        // Parse the input data
        ucl_parser_add_chunk(parser, data, size);
        root = ucl_parser_get_object(parser);
    }

    // Create a new UCL object to append
    element = ucl_object_fromstring("fuzz_element");

    // Call the function under test
    if (root != NULL && element != NULL) {
        ucl_array_append(root, element);
    }

    // Clean up
    if (root != NULL) {
        ucl_object_unref(root);
    }
    if (element != NULL) {
        ucl_object_unref(element);
    }
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

    LLVMFuzzerTestOneInput_172(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
