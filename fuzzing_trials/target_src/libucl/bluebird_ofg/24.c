#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
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
        unsigned char *result = ucl_object_emit(obj, emitter_type);

        // Free the result if it's not NULL
        if (result != NULL) {
            free(result);
        }

        // Free the UCL object

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_emit to ucl_parser_register_macro
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        unsigned char ret_ucl_parser_chunk_peek_whrry = ucl_parser_chunk_peek(parser);
        // Ensure dataflow is valid (i.e., non-null)
        if (!obj) {
        	return 0;
        }
        ucl_object_t* ret_ucl_array_pop_last_vvrdm = ucl_array_pop_last(obj);
        if (ret_ucl_array_pop_last_vvrdm == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!result) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!obj) {
        	return 0;
        }
        bool ret_ucl_parser_register_macro_tvbjx = ucl_parser_register_macro(parser, (const char *)result, NULL, (void *)obj);
        if (ret_ucl_parser_register_macro_tvbjx == 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
