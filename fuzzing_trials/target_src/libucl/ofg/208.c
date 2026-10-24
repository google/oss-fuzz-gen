#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    ucl_object_t *original_obj = NULL;
    ucl_object_t *copied_obj = NULL;

    // Ensure data is not NULL and size is greater than zero
    if (data == NULL || size == 0) {
        return 0;
    }

    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data into a UCL object
    if (ucl_parser_add_chunk(parser, data, size)) {
        original_obj = ucl_parser_get_object(parser);
    }

    // If parsing was successful, copy the UCL object
    if (original_obj != NULL) {
        copied_obj = ucl_object_copy(original_obj);
    }

    // Clean up
    if (original_obj != NULL) {
        ucl_object_unref(original_obj);
    }
    if (copied_obj != NULL) {
        ucl_object_unref(copied_obj);
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

    LLVMFuzzerTestOneInput_208(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
