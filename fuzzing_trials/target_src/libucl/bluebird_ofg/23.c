#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Initialize UCL parser
    struct ucl_parser *parser = ucl_parser_new(0);
    ucl_object_t *obj = NULL;
    int64_t result = 0;
    
    // Parse the input data
    if (parser != NULL && ucl_parser_add_chunk(parser, data, size)) {
        obj = ucl_parser_get_object(parser);
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_parser_get_object to ucl_elt_append
        ucl_object_t* ret_ucl_object_new_ffprr = ucl_object_new();
        if (ret_ucl_object_new_ffprr == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_ucl_object_new_ffprr) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!obj) {
        	return 0;
        }
        ucl_object_t* ret_ucl_elt_append_mrmws = ucl_elt_append(ret_ucl_object_new_ffprr, obj);
        if (ret_ucl_elt_append_mrmws == NULL){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Ensure obj is not NULL before calling the function-under-test
    if (obj != NULL) {
        // Call the function-under-test
        bool success = ucl_object_toint_safe(obj, &result);
        
        // Use the result to avoid unused variable warning
        if (success) {
            // Do something with result if necessary
        }
    }

    // Cleanup
    if (obj != NULL) {
        ucl_object_unref(obj);
    }
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
