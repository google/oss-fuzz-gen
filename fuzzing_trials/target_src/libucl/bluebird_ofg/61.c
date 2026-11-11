#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "ucl.h"

// Function-under-test
bool ucl_object_toboolean(const ucl_object_t *obj);

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    ucl_object_t *ucl_obj;
    struct ucl_parser *parser;

    if (size == 0) {
        return 0;
    }

    // Initialize a UCL parser
    parser = ucl_parser_new(0);

    // Try to parse the input data as a UCL object
    if (ucl_parser_add_chunk(parser, data, size)) {
        ucl_obj = ucl_parser_get_object(parser);
        if (ucl_obj != NULL) {
            // Call the function-under-test
            bool result = ucl_object_toboolean(ucl_obj);

            // Clean up
            ucl_object_unref(ucl_obj);
        }
    }

    // Clean up parser
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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
