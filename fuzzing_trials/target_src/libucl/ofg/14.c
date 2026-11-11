#include <stdbool.h>
#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize UCL parser
    struct ucl_parser *parser1 = ucl_parser_new(0);
    struct ucl_parser *parser2 = ucl_parser_new(0);

    // Ensure the parsers are not NULL
    if (parser1 == NULL || parser2 == NULL) {
        if (parser1 != NULL) {
            ucl_parser_free(parser1);
        }
        if (parser2 != NULL) {
            ucl_parser_free(parser2);
        }
        return 0;
    }

    // Parse the input data into UCL objects
    ucl_parser_add_chunk(parser1, data, size);
    ucl_parser_add_chunk(parser2, data, size);

    // Get the UCL objects
    ucl_object_t *obj1 = ucl_parser_get_object(parser1);
    ucl_object_t *obj2 = ucl_parser_get_object(parser2);

    // Ensure the objects are not NULL
    if (obj1 == NULL || obj2 == NULL) {
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

    // Call the function under test
    bool merge_result = ucl_object_merge(obj1, obj2, true);

    // Clean up
    ucl_object_unref(obj1);
    ucl_object_unref(obj2);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
