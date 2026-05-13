#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize ucl_object_t pointers
    ucl_object_t *array_obj = NULL;
    ucl_object_t *search_obj = NULL;

    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);

    // Parse the input data to create a UCL object
    if (ucl_parser_add_chunk(parser, data, size)) {
        array_obj = ucl_parser_get_object(parser);
    }

    // If the parsed object is an array, use it as the array_obj
    if (array_obj != NULL && ucl_object_type(array_obj) == UCL_ARRAY) {
        // Create another UCL object to search for within the array
        search_obj = ucl_object_fromstring("test");

        // Call the function-under-test
        unsigned int index = ucl_array_index_of(array_obj, search_obj);

        // Clean up the search object
        ucl_object_unref(search_obj);
    }

    // Clean up the parser and array object
    if (array_obj != NULL) {
        ucl_object_unref(array_obj);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
