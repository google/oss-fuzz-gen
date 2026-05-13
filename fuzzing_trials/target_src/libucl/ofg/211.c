#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    ucl_object_t *ucl_obj;
    const char *result_str;
    size_t result_len;

    // Ensure data is not empty to create a valid UCL object
    if (size == 0) {
        return 0;
    }

    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);

    // Parse the input data into a UCL object
    if (!ucl_parser_add_chunk(parser, data, size)) {
        ucl_parser_free(parser);
        return 0;
    }

    // Get the UCL object from the parser
    ucl_obj = ucl_parser_get_object(parser);

    // Call the function-under-test
    bool success = ucl_object_tolstring_safe(ucl_obj, &result_str, &result_len);

    // Clean up
    ucl_object_unref(ucl_obj);
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

    LLVMFuzzerTestOneInput_211(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
