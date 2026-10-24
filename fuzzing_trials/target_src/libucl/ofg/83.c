#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    ucl_object_t *ucl_obj = NULL;
    const ucl_object_t *result = NULL;

    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data as UCL
    ucl_parser_add_chunk(parser, data, size);

    // Get the parsed UCL object
    ucl_obj = ucl_parser_get_object(parser);

    // Ensure the object is not NULL before proceeding
    if (ucl_obj != NULL) {
        // Use a fixed key for lookup
        const char *key = "example_key";
        size_t key_len = strlen(key);

        // Call the function under test
        result = ucl_object_lookup_len(ucl_obj, key, key_len);

        // Optionally, do something with the result
        if (result != NULL) {
            // For example, just access the type of the result
            ucl_type_t type = ucl_object_type(result);
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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
