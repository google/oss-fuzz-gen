#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Ensure there is enough data to split into two parts for two ucl_object_t objects
    if (size < 2) {
        return 0;
    }

    // Create two ucl_parser objects
    struct ucl_parser *parser1 = ucl_parser_new(0);
    struct ucl_parser *parser2 = ucl_parser_new(0);

    // Split the input data into two parts
    size_t half_size = size / 2;

    // Parse the first half of the data into the first ucl_object_t
    ucl_parser_add_chunk(parser1, data, half_size);
    const ucl_object_t *obj1 = ucl_parser_get_object(parser1);

    // Parse the second half of the data into the second ucl_object_t
    ucl_parser_add_chunk(parser2, data + half_size, size - half_size);
    const ucl_object_t *obj2 = ucl_parser_get_object(parser2);

    // Call the function-under-test
    if (obj1 != NULL && obj2 != NULL) {
        int result = ucl_object_compare(obj1, obj2);
    }

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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
