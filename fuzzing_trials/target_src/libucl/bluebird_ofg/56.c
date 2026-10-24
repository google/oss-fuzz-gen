#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure the size is at least 1 to extract a flag
    if (size < 1) {
        return 0;
    }

    // Extract the flag from the data
    enum ucl_string_flags flags = (enum ucl_string_flags)data[0];

    // Ensure the string is not empty
    const char *inputString = (const char *)(data + 1);
    size_t stringSize = size - 1;

    // Call the function under test
    ucl_object_t *result = ucl_object_fromstring_common(inputString, stringSize, flags);

    // Clean up the result if needed
    if (result != NULL) {
        ucl_object_unref(result);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_fromstring_common to ucl_comments_find

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_fromstring_common to ucl_object_iterate_reset
    const ucl_object_t sijnrwmg;
    memset(&sijnrwmg, 0, sizeof(sijnrwmg));
    ucl_object_iter_t ret_ucl_object_iterate_new_pwigb = ucl_object_iterate_new(&sijnrwmg);
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }
    ucl_object_iter_t ret_ucl_object_iterate_reset_fcmlo = ucl_object_iterate_reset(ret_ucl_object_iterate_new_pwigb, result);
    // End mutation: Producer.APPEND_MUTATOR
    
    ucl_object_t* ret_ucl_object_fromdouble_vehal = ucl_object_fromdouble(UCL_PRIORITY_MIN);
    if (ret_ucl_object_fromdouble_vehal == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromdouble_vehal) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_fromdouble to ucl_object_insert_key
    ucl_object_t* ret_ucl_object_fromint_hsaqw = ucl_object_fromint(64);
    if (ret_ucl_object_fromint_hsaqw == NULL){
    	return 0;
    }
    char *iavnydcw[1024] = {"gokec", NULL};
    struct ucl_emitter_functions* ret_ucl_object_emit_memory_funcs_lbhoe = ucl_object_emit_memory_funcs(iavnydcw);
    if (ret_ucl_object_emit_memory_funcs_lbhoe == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromdouble_vehal) {
    	return 0;
    }
    int64_t ret_ucl_object_toint_wllle = ucl_object_toint(ret_ucl_object_fromdouble_vehal);
    if (ret_ucl_object_toint_wllle < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromint_hsaqw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromdouble_vehal) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!iavnydcw) {
    	return 0;
    }
    bool ret_ucl_object_insert_key_scdsc = ucl_object_insert_key(ret_ucl_object_fromint_hsaqw, ret_ucl_object_fromdouble_vehal, (const char *)*iavnydcw, (size_t )ret_ucl_object_toint_wllle, 1);
    if (ret_ucl_object_insert_key_scdsc == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    const ucl_object_t* ret_ucl_comments_find_vdvrm = ucl_comments_find(ret_ucl_object_fromdouble_vehal, result);
    if (ret_ucl_comments_find_vdvrm == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
