#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize UCL parser
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of ucl_parser_new
    struct ucl_parser *parser = ucl_parser_new(-1);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (parser == NULL) {
        return 0;
    }

    // Parse the input data
    ucl_parser_add_chunk(parser, data, size);
    const ucl_object_t *obj = ucl_parser_get_object(parser);

    if (obj != NULL) {
        // Define a ucl_emitter value
        enum ucl_emitter emitter_type = UCL_EMIT_JSON;

        // Call the function-under-test
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of ucl_object_emit
        unsigned char *result = ucl_object_emit(obj, UCL_EMIT_MSGPACK);
        // End mutation: Producer.REPLACE_ARG_MUTATOR

        // Free the result if it's not NULL
        if (result != NULL) {
            free(result);
        }

        // Free the UCL object
        ucl_object_unref(obj);
    }

    // Clean up the parser

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from ucl_parser_get_object to ucl_object_compare_qsort using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from ucl_parser_get_object to ucl_object_reserve using the plateau pool
    size_t reserve_size = (size_t)data[0];
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    bool ret_ucl_object_reserve_dxzrb = ucl_object_reserve(obj, reserve_size);
    if (ret_ucl_object_reserve_dxzrb == 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    int ret_ucl_object_compare_qsort_czisc = ucl_object_compare_qsort(&obj, &obj);
    if (ret_ucl_object_compare_qsort_czisc < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
