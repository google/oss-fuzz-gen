#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Initialize required variables
    ucl_object_iter_t iter = NULL;
    ucl_object_t *obj = NULL;
    
    // Create a UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);

    // Check if parser creation was successful
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    if (ucl_parser_add_chunk(parser, data, size)) {
        // Get the parsed object
        obj = ucl_parser_get_object(parser);
        
        // Call the function-under-test
        iter = ucl_object_iterate_reset(iter, obj);
        
        // Clean up
        ucl_object_unref(obj);
    }

    // Free the parser
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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
