#include <stdint.h>
#include <ucl.h>
#include <stdlib.h>
#include <stdbool.h>

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    struct ucl_parser *parser = NULL;
    ucl_object_t *obj = NULL;

    // Initialize the parser
    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

    // Create a dummy UCL object
    obj = ucl_object_new_full(UCL_OBJECT, 0);

    // Ensure data is not empty and can be used as a string
    if (size > 0 && data[size - 1] == '\0') {
        // Attempt to parse the input data as a UCL object
        ucl_parser_add_chunk(parser, data, size);

        // Call the function under test
        ucl_set_include_path(parser, obj);
    }

    // Clean up
    if (parser != NULL) {
        ucl_parser_free(parser);
    }
    if (obj != NULL) {
        ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
