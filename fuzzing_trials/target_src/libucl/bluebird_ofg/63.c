#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
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

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_emit to ucl_parser_add_chunk_full
        struct ucl_parser* ret_ucl_parser_new_mgkru = ucl_parser_new(UCL_PRIORITY_MAX);
        if (ret_ucl_parser_new_mgkru == NULL){
        	return 0;
        }
        unsigned int ret_ucl_parser_get_column_ggjnc = ucl_parser_get_column(NULL);
        if (ret_ucl_parser_get_column_ggjnc < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        unsigned int ret_ucl_parser_get_linenum_vpzar = ucl_parser_get_linenum(parser);
        if (ret_ucl_parser_get_linenum_vpzar < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_ucl_parser_new_mgkru) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!result) {
        	return 0;
        }
        bool ret_ucl_parser_add_chunk_full_cmnrz = ucl_parser_add_chunk_full(ret_ucl_parser_new_mgkru, result, (size_t )ret_ucl_parser_get_column_ggjnc, ret_ucl_parser_get_linenum_vpzar, UCL_DUPLICATE_MERGE, UCL_PARSE_AUTO);
        if (ret_ucl_parser_add_chunk_full_cmnrz == 0){
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
