#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there is enough data for two objects

    // Initialize the UCL parser
    struct ucl_parser *parser1 = ucl_parser_new(0);
    struct ucl_parser *parser2 = ucl_parser_new(0);

    // Split the data into two parts for two UCL objects
    size_t half_size = size / 2;

    // Parse the first part of the data into a UCL object
    ucl_parser_add_chunk(parser1, data, half_size);
    const ucl_object_t *obj1 = ucl_parser_get_object(parser1);

    // Parse the second part of the data into another UCL object
    ucl_parser_add_chunk(parser2, data + half_size, size - half_size);
    const ucl_object_t *obj2 = ucl_parser_get_object(parser2);

    // Ensure both objects are not NULL before comparison
    if (obj1 != NULL && obj2 != NULL) {
        // Call the function under test
        int result = ucl_object_compare(obj1, obj2);
    }

    // Clean up
    if (obj1 != NULL) {
        ucl_object_unref(obj1);
    }
    if (obj2 != NULL) {
        ucl_object_unref(obj2);
    }
    ucl_parser_free(parser1);
    ucl_parser_free(parser2);

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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
