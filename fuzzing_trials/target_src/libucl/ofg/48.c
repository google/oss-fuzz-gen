#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <ucl.h>
#include <string.h>

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Initialize a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    const ucl_object_t *root_obj = NULL;
    const ucl_object_t *result_obj = NULL;

    // Ensure the data is null-terminated for parsing
    char *data_copy = (char *)malloc(size + 1);
    if (data_copy == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Parse the input data
    if (ucl_parser_add_chunk(parser, (const unsigned char *)data_copy, size)) {
        // Get the root object from the parser
        root_obj = ucl_parser_get_object(parser);

        // Use a sample key to lookup in the UCL object
        const char *sample_key = "sample_key";
        
        // Call the function-under-test
        result_obj = ucl_object_lookup(root_obj, sample_key);
    }

    // Clean up
    if (root_obj != NULL) {
        ucl_object_unref(root_obj);
    }
    ucl_parser_free(parser);
    free(data_copy);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
