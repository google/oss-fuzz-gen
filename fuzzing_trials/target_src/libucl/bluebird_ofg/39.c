#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    ucl_object_t *obj1 = NULL;
    ucl_object_t *obj2 = NULL;
    bool merge_result = false;

    // Ensure that the data is not empty
    if (size > 0) {
        // Create a UCL parser
        struct ucl_parser *parser = ucl_parser_new(0);

        // Parse the input data into the first UCL object
        if (ucl_parser_add_chunk(parser, data, size)) {
            obj1 = ucl_parser_get_object(parser);
        
            // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from ucl_parser_get_object to ucl_object_reserve using the plateau pool
            size_t reserve_size = (size_t)data[0];
            // Ensure dataflow is valid (i.e., non-null)
            if (!obj1) {
            	return 0;
            }
            bool ret_ucl_object_reserve_bqtuw = ucl_object_reserve(obj1, reserve_size);
            if (ret_ucl_object_reserve_bqtuw == 0){
            	return 0;
            }
            // End mutation: Producer.SPLICE_MUTATOR
            
}

        // Clean up the parser and create a new one for the second object
        ucl_parser_free(parser);
        parser = ucl_parser_new(0);

        // Parse the input data into the second UCL object
        if (ucl_parser_add_chunk(parser, data, size)) {
            obj2 = ucl_parser_get_object(parser);
        }

        // Clean up the parser
        ucl_parser_free(parser);
    }

    // Call the function-under-test if both objects are created
    if (obj1 && obj2) {
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of ucl_array_merge
        merge_result = ucl_array_merge(obj1, obj2, 0);
        // End mutation: Producer.REPLACE_ARG_MUTATOR
    }

    // Clean up UCL objects
    if (obj1) {
        ucl_object_unref(obj1);
    }
    if (obj2) {
        ucl_object_unref(obj2);
    }

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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
