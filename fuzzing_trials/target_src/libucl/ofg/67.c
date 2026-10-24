#include <stdint.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    struct ucl_parser *parser = ucl_parser_new(0);
    ucl_object_t *obj = ucl_object_new();

    if (parser == NULL || obj == NULL) {
        if (parser != NULL) {
            ucl_parser_free(parser);
        }
        if (obj != NULL) {
            ucl_object_unref(obj);
        }
        return 0;
    }

    // Initialize obj with some data if needed
    ucl_object_t *str_obj = ucl_object_fromstring_common((const char *)data, size, 0);

    if (str_obj != NULL) {
        // Call the function-under-test
        bool result = ucl_set_include_path(parser, str_obj);

        // Unref the string object after use
        ucl_object_unref(str_obj);
    }

    // Clean up
    ucl_parser_free(parser);
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
