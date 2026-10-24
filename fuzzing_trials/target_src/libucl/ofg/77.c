#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Function-under-test
char *ucl_copy_key_trash(const ucl_object_t *obj);

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a ucl_object_t
    if (size == 0) {
        return 0;
    }

    // Initialize a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Create a UCL object from the input data
    ucl_object_t *ucl_obj = NULL;
    ucl_parser_add_chunk(parser, data, size);
    ucl_obj = ucl_parser_get_object(parser);

    // Call the function-under-test
    if (ucl_obj != NULL) {
        char *result = ucl_copy_key_trash(ucl_obj);
        // Free the result if it's not NULL
        if (result != NULL) {
            free(result);
        }
        ucl_object_unref(ucl_obj);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
