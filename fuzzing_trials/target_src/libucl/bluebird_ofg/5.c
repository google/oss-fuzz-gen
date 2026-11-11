#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "ucl.h"

extern int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize a ucl_object_t
    ucl_object_t *obj = ucl_object_new();

    // Ensure that the ucl_object_t is not NULL
    if (obj == NULL) {
        return 0;
    }

    // Create a buffer for the data and parse it into the ucl_object_t
    struct ucl_parser *parser = ucl_parser_new(0);
    if (parser == NULL) {
        ucl_object_unref(obj);
        return 0;
    }

    ucl_parser_add_chunk(parser, data, size);
    ucl_object_t *parsed_obj = ucl_parser_get_object(parser);

    // If parsing was successful, replace the original object
    if (parsed_obj != NULL) {
        ucl_object_unref(obj);
        obj = parsed_obj;
    }

    // Define a sort flag (using a valid enumeration value)
    enum ucl_object_keys_sort_flags sort_flag = UCL_SORT_KEYS_DEFAULT;

    // Call the function-under-test
    ucl_object_sort_keys(obj, sort_flag);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_sort_keys to ucl_array_index_of
    // Ensure dataflow is valid (i.e., non-null)
    if (!parsed_obj) {
    	return 0;
    }
    ucl_object_t* ret_ucl_array_pop_first_cqcif = ucl_array_pop_first(parsed_obj);
    if (ret_ucl_array_pop_first_cqcif == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!parsed_obj) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    unsigned int ret_ucl_array_index_of_bevid = ucl_array_index_of(parsed_obj, obj);
    if (ret_ucl_array_index_of_bevid < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_array_index_of to ucl_array_find_index
    ucl_object_t* ret_ucl_array_pop_first_qcutx = ucl_array_pop_first(ret_ucl_array_pop_first_cqcif);
    if (ret_ucl_array_pop_first_qcutx == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_array_pop_first_cqcif) {
    	return 0;
    }
    const ucl_object_t* ret_ucl_array_find_index_yxcfz = ucl_array_find_index(ret_ucl_array_pop_first_cqcif, ret_ucl_array_index_of_bevid);
    if (ret_ucl_array_find_index_yxcfz == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
