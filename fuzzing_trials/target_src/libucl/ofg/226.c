#include <stdint.h>
#include <stddef.h>
#include "/src/libucl/include/ucl.h"

// Include the necessary standard library for memory deallocation
#include <stdlib.h>

int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    // Ensure the input data is non-empty
    if (size == 0) {
        return 0;
    }

    // Initialize UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    if (!ucl_parser_add_chunk(parser, data, size)) {
        ucl_parser_free(parser);
        return 0;
    }

    // Get the root object
    const ucl_object_t *root = ucl_parser_get_object(parser);
    if (root == NULL) {
        ucl_parser_free(parser);
        return 0;
    }

    // Define a valid ucl_emitter value
    ucl_emitter_t emitter_type = UCL_EMIT_JSON;

    // Call the function-under-test
    unsigned char *result = ucl_object_emit(root, emitter_type);

    // Free the result if it is not NULL
    if (result != NULL) {
        // Use standard free function for memory allocated by ucl_object_emit
        free(result);
    }

    // Clean up
    ucl_object_unref(root);
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

    LLVMFuzzerTestOneInput_226(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
