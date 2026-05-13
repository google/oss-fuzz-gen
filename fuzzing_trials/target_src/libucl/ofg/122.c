#include <stdint.h>
#include <stddef.h>
#include <ucl.h>
#include <string.h>  // Include string.h for strlen

// Define a comparison function for sorting
int custom_compare(const ucl_object_t **a, const ucl_object_t **b) {
    // Use strlen to compare the length of the keys
    return (int)(strlen(ucl_object_key(*a)) - strlen(ucl_object_key(*b)));
}

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    ucl_object_t *array = NULL;
    ucl_object_t *obj = NULL;
    struct ucl_parser *parser = NULL;

    // Initialize a UCL parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    if (!ucl_parser_add_chunk(parser, data, size)) {
        ucl_parser_free(parser);
        return 0;
    }

    // Get the top-level object
    obj = ucl_parser_get_object(parser);
    if (obj == NULL) {
        ucl_parser_free(parser);
        return 0;
    }

    // Check if the object is an array
    if (ucl_object_type(obj) == UCL_ARRAY) {
        array = obj;
    } else {
        // Clean up if the object is not an array
        ucl_object_unref(obj);
        ucl_parser_free(parser);
        return 0;
    }

    // Call the function-under-test
    ucl_object_array_sort(array, custom_compare);

    // Clean up
    ucl_object_unref(obj);
    ucl_parser_free(parser);

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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
