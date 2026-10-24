#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
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
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of ucl_object_emit
        unsigned char *result = ucl_object_emit(obj, UCL_EMIT_CONFIG);
        // End mutation: Producer.REPLACE_ARG_MUTATOR

        // Free the result if it's not NULL
        if (result != NULL) {
            free(result);
        }

        // Free the UCL object
        ucl_object_unref(obj);
    }

    // Clean up the parser

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_parser_get_object to ucl_set_include_path
    struct ucl_parser* ret_ucl_parser_new_khqgc = ucl_parser_new(UCL_PRIORITY_MIN);
    if (ret_ucl_parser_new_khqgc == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_parser_new_khqgc) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    bool ret_ucl_set_include_path_opozz = ucl_set_include_path(ret_ucl_parser_new_khqgc, obj);
    if (ret_ucl_set_include_path_opozz == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_set_include_path to ucl_object_replace_key
    ucl_object_t* ret_ucl_object_fromint_fhsqx = ucl_object_fromint(0);
    if (ret_ucl_object_fromint_fhsqx == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_parser_new_khqgc) {
    	return 0;
    }
    struct ucl_emitter_functions* ret_ucl_object_emit_memory_funcs_unntq = ucl_object_emit_memory_funcs((void **)&ret_ucl_parser_new_khqgc);
    if (ret_ucl_object_emit_memory_funcs_unntq == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_emit_memory_funcs to ucl_parser_register_macro
    struct ucl_parser* ret_ucl_parser_new_odnny = ucl_parser_new(-1);
    if (ret_ucl_parser_new_odnny == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromint_fhsqx) {
    	return 0;
    }
    char* ret_ucl_copy_value_trash_hiaat = ucl_copy_value_trash(ret_ucl_object_fromint_fhsqx);
    if (ret_ucl_copy_value_trash_hiaat == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_parser_new_odnny) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_copy_value_trash_hiaat) {
    	return 0;
    }
    bool ret_ucl_parser_register_macro_ooqwh = ucl_parser_register_macro(ret_ucl_parser_new_odnny, &ret_ucl_parser_new_khqgc, &ret_ucl_parser_new_khqgc, (void *)ret_ucl_copy_value_trash_hiaat);
    if (ret_ucl_parser_register_macro_ooqwh == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int64_t ret_ucl_object_toint_jauca = ucl_object_toint(obj);
    if (ret_ucl_object_toint_jauca < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromint_fhsqx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    bool ret_ucl_object_replace_key_bmjin = ucl_object_replace_key(ret_ucl_object_fromint_fhsqx, obj, &ret_ucl_parser_new_khqgc, (size_t )ret_ucl_object_toint_jauca, 1);
    if (ret_ucl_object_replace_key_bmjin == 0){
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
