#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Initialize the UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    const ucl_object_t *obj1 = NULL;
    const ucl_object_t *obj2 = NULL;
    const ucl_object_t *result;

    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Attempt to parse the input data into a UCL object
    if (ucl_parser_add_chunk(parser, data, size)) {
        obj1 = ucl_parser_get_object(parser);
    }

    // Use the same object for both parameters for simplicity
    obj2 = obj1;

    // Call the function under test
    result = ucl_comments_find(obj1, obj2);

    // Clean up
    if (obj1) {
        ucl_object_unref(obj1);
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
