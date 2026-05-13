#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_201(const uint8_t *data, size_t size) {
    ucl_object_t *ucl_obj = NULL;
    ucl_object_iter_t iter = NULL;
    struct ucl_parser *parser = ucl_parser_new(0);

    if (parser == NULL || size == 0) {
        return 0;
    }

    // Parse the input data into a UCL object
    ucl_parser_add_chunk(parser, data, size);

    // Get the root object
    ucl_obj = ucl_parser_get_object(parser);
    if (ucl_obj != NULL) {
        // Call the function-under-test
        iter = ucl_object_iterate_new(ucl_obj);

        // Clean up
        ucl_object_iterate_free(iter);
        ucl_object_unref(ucl_obj);
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

    LLVMFuzzerTestOneInput_201(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
