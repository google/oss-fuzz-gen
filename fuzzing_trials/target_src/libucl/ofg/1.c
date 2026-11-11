#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    ucl_object_t *array = NULL;
    ucl_object_t *element = NULL;
    struct ucl_parser *parser = NULL;

    if (size < 2) {
        return 0;
    }

    // Initialize UCL parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the data into a UCL object
    if (ucl_parser_add_chunk(parser, data, size)) {
        array = ucl_parser_get_object(parser);
    }

    // Create a simple element object for testing
    element = ucl_object_fromstring("test");

    if (array != NULL && element != NULL) {
        // Call the function-under-test
        unsigned int index = ucl_array_index_of(array, element);
    }

    // Clean up
    if (array != NULL) {
        ucl_object_unref(array);
    }
    if (element != NULL) {
        ucl_object_unref(element);
    }
    if (parser != NULL) {
        ucl_parser_free(parser);
    }

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
