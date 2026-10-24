#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to proceed
    }

    // Initialize UCL parser
    struct ucl_parser *parser1 = ucl_parser_new(0);
    struct ucl_parser *parser2 = ucl_parser_new(0);

    if (parser1 == NULL || parser2 == NULL) {
        if (parser1 != NULL) ucl_parser_free(parser1);
        if (parser2 != NULL) ucl_parser_free(parser2);
        return 0;
    }

    // Split the input data into two parts for two UCL objects
    size_t half_size = size / 2;
    const uint8_t *data1 = data;
    size_t size1 = half_size;
    const uint8_t *data2 = data + half_size;
    size_t size2 = size - half_size;

    // Parse the first part of the data
    ucl_parser_add_chunk(parser1, data1, size1);
    ucl_object_t *obj1 = ucl_parser_get_object(parser1);

    // Parse the second part of the data
    ucl_parser_add_chunk(parser2, data2, size2);
    ucl_object_t *obj2 = ucl_parser_get_object(parser2);

    // Ensure the objects are not NULL
    if (obj1 != NULL && obj2 != NULL) {
        // Use the first byte of the data to determine the boolean value
        bool merge_recursively = (data[0] % 2 == 0);

        // Call the function-under-test
        ucl_object_merge(obj1, obj2, merge_recursively);
    }

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
