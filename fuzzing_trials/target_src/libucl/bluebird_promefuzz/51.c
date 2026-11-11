#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
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
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_emit to ucl_parser_insert_chunk
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        int ret_ucl_parser_get_default_priority_rkitt = ucl_parser_get_default_priority(parser);
        if (ret_ucl_parser_get_default_priority_rkitt < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!top_obj) {
        	return 0;
        }
        unsigned int ret_ucl_array_size_ovbvn = ucl_array_size(top_obj);
        if (ret_ucl_array_size_ovbvn < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!output) {
        	return 0;
        }

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_array_size to ucl_object_fromlstring
        // Ensure dataflow is valid (i.e., non-null)
        if (!top_obj) {
        	return 0;
        }
        char* ret_ucl_copy_value_trash_xkyki = ucl_copy_value_trash(top_obj);
        if (ret_ucl_copy_value_trash_xkyki == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_ucl_copy_value_trash_xkyki) {
        	return 0;
        }

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_copy_value_trash to ucl_parser_add_string
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        int ret_ucl_parser_get_default_priority_yurol = ucl_parser_get_default_priority(parser);
        if (ret_ucl_parser_get_default_priority_yurol < 0){
        	return 0;
        }
        const ucl_object_t rikzhqot;
        memset(&rikzhqot, 0, sizeof(rikzhqot));
        unsigned int ret_ucl_array_size_lldju = ucl_array_size(&rikzhqot);
        if (ret_ucl_array_size_lldju < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!parser) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_ucl_copy_value_trash_xkyki) {
        	return 0;
        }
        bool ret_ucl_parser_add_string_gmnqa = ucl_parser_add_string(parser, ret_ucl_copy_value_trash_xkyki, (size_t )ret_ucl_array_size_lldju);
        if (ret_ucl_parser_add_string_gmnqa == 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        ucl_object_t* ret_ucl_object_fromlstring_qteck = ucl_object_fromlstring(ret_ucl_copy_value_trash_xkyki, (size_t )ret_ucl_array_size_ovbvn);
        if (ret_ucl_object_fromlstring_qteck == NULL){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        bool ret_ucl_parser_insert_chunk_bjbke = ucl_parser_insert_chunk(parser, output, (size_t )ret_ucl_array_size_ovbvn);
        if (ret_ucl_parser_insert_chunk_bjbke == 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
