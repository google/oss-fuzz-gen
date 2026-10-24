#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for testing
    if (size < 2) {
        return 0;
    }

    // Initialize UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data into a UCL object
    ucl_parser_add_chunk(parser, data, size);
    const ucl_object_t *ucl_obj = ucl_parser_get_object(parser);
    if (ucl_obj == NULL) {
        ucl_parser_free(parser);
        return 0;
    }

    // Prepare a path string from the input data
    size_t path_len = size / 2;
    char *path = (char *)malloc(path_len + 1);
    if (path == NULL) {
        ucl_object_unref(ucl_obj);
        ucl_parser_free(parser);
        return 0;
    }
    memcpy(path, data + path_len, path_len);
    path[path_len] = '\0';

    // Call the function-under-test
    const ucl_object_t *result = ucl_object_lookup_path(ucl_obj, path);

    // Clean up
    free(path);
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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
