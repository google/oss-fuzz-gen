#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    struct ucl_parser *parser;

    // Initialize the UCL parser
    parser = ucl_parser_new(0);
    if (parser == NULL) {
        return 0;
    }

    // Feed the parser with input data
    if (size > 0) {
        ucl_parser_add_chunk(parser, data, size);
    }

    // Call the function-under-test
    unsigned char result = ucl_parser_chunk_peek(parser);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_parser_chunk_peek to ucl_parser_insert_chunk
    // Ensure dataflow is valid (i.e., non-null)
    if (!parser) {
    	return 0;
    }
    int ret_ucl_parser_get_error_code_mrztj = ucl_parser_get_error_code(parser);
    if (ret_ucl_parser_get_error_code_mrztj < 0){
    	return 0;
    }
    unsigned int ret_ucl_parser_get_linenum_uwaro = ucl_parser_get_linenum(NULL);
    if (ret_ucl_parser_get_linenum_uwaro < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!parser) {
    	return 0;
    }
    bool ret_ucl_parser_insert_chunk_jkfvy = ucl_parser_insert_chunk(parser, &result, (size_t )ret_ucl_parser_get_linenum_uwaro);
    if (ret_ucl_parser_insert_chunk_jkfvy == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
