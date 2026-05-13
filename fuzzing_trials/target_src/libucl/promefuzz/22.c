// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_parser_new at ucl_parser.c:2826:1 in ucl.h
// ucl_parser_add_chunk at ucl_parser.c:3131:6 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_parser_get_object at ucl_util.c:590:1 in ucl.h
// ucl_parser_get_error at ucl_util.c:665:1 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    // Step 1: Prepare the environment
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Step 2: Add chunk to parser
    if (!ucl_parser_add_chunk(parser, Data, Size)) {
        // Cleanup if adding chunk fails
        ucl_parser_free(parser);
        return 0;
    }

    // Step 3: Get the top object from the parser
    ucl_object_t *top_obj = ucl_parser_get_object(parser);
    if (top_obj == NULL) {
        // Retrieve and print error if object retrieval fails
        const char *error = ucl_parser_get_error(parser);
        if (error != NULL) {
            fprintf(stderr, "Error: %s\n", error);
        }
        ucl_parser_free(parser);
        return 0;
    }

    // Step 4: Emit the object in various formats
    for (int i = UCL_EMIT_JSON; i < UCL_EMIT_MAX; i++) {
        unsigned char *output = ucl_object_emit(top_obj, (enum ucl_emitter)i);
        if (output != NULL) {
            // Use the emitted output
            free(output);
        }
    }

    // Step 5: Cleanup
    ucl_parser_free(parser);
    ucl_object_unref(top_obj);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
