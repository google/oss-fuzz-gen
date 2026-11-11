#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Initialize ucl parser
    struct ucl_parser *parser1 = ucl_parser_new(0);
    struct ucl_parser *parser2 = ucl_parser_new(0);

    // Check if parsers are successfully created
    if (parser1 == NULL || parser2 == NULL) {
        if (parser1 != NULL) ucl_parser_free(parser1);
        if (parser2 != NULL) ucl_parser_free(parser2);
        return 0;
    }

    // Parse the input data into two separate ucl objects
    ucl_parser_add_chunk(parser1, data, size);
    ucl_parser_add_chunk(parser2, data, size);

    const ucl_object_t *obj1 = ucl_parser_get_object(parser1);
    const ucl_object_t *obj2 = ucl_parser_get_object(parser2);

    // Call the function-under-test
    const ucl_object_t *result = ucl_comments_find(obj1, obj2);

    // Clean up
    if (obj1 != NULL) ucl_object_unref(obj1);
    if (obj2 != NULL) ucl_object_unref(obj2);
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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
