#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Initialize a ucl_parser object
    struct ucl_parser *parser = ucl_parser_new(0);
    ucl_object_t *ucl_obj = NULL;

    // Check if the parser was created successfully
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    if (ucl_parser_add_chunk(parser, data, size)) {
        // Get the top UCL object
        ucl_obj = ucl_parser_get_object(parser);

        // Call the function-under-test
        if (ucl_obj != NULL) {
            int64_t result = ucl_object_toint(ucl_obj);
        }

        // Free the UCL object
        ucl_object_unref(ucl_obj);
    }

    // Clean up the parser
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
