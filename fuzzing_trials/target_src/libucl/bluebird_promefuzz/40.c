#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ucl.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *fp = fopen("./dummy_file", "wb");
    if (fp != NULL) {
        fwrite(Data, 1, Size, fp);
        fclose(fp);
    }
}

int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare the environment
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    if (!obj) {
        return 0;
    }

    const char *str = (const char *)Data;
    size_t len = Size;
    enum ucl_string_flags flags = UCL_STRING_PARSE;

    // Convert string to UCL object
    ucl_object_t *string_obj1 = ucl_object_fromstring_common(str, len, flags);
    if (!string_obj1) {
        goto cleanup;
    }

    // Insert key-value pair
    if (!ucl_object_insert_key(obj, string_obj1, "key1", 4, true)) {
        goto cleanup;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_insert_key to ucl_object_insert_key_merged
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from ucl_object_fromstring_common to ucl_object_iterate_with_error using the plateau pool
    ucl_object_iter_t iter = NULL;
    int error = 0;
    // Ensure dataflow is valid (i.e., non-null)
    if (!string_obj1) {
    	return 0;
    }
    const ucl_object_t* ret_ucl_object_iterate_with_error_oheta = ucl_object_iterate_with_error(string_obj1, &iter, true, &error);
    if (ret_ucl_object_iterate_with_error_oheta == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    ucl_object_t* ret_ucl_object_ref_woitg = ucl_object_ref(obj);
    if (ret_ucl_object_ref_woitg == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    char* ret_ucl_copy_value_trash_wgeys = ucl_copy_value_trash(obj);
    if (ret_ucl_copy_value_trash_wgeys == NULL){
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_copy_value_trash to ucl_object_tostring_safe
    ucl_object_t* ret_ucl_object_fromint_czjsd = ucl_object_fromint(UCL_PRIORITY_MIN);
    if (ret_ucl_object_fromint_czjsd == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_fromint_czjsd) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_copy_value_trash_wgeys) {
    	return 0;
    }
    bool ret_ucl_object_tostring_safe_hlhtg = ucl_object_tostring_safe(ret_ucl_object_fromint_czjsd, &ret_ucl_copy_value_trash_wgeys);
    if (ret_ucl_object_tostring_safe_hlhtg == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    double ret_ucl_object_todouble_wgwaf = ucl_object_todouble(NULL);
    if (ret_ucl_object_todouble_wgwaf < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_ref_woitg) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!string_obj1) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_copy_value_trash_wgeys) {
    	return 0;
    }
    bool ret_ucl_object_insert_key_merged_eowpt = ucl_object_insert_key_merged(ret_ucl_object_ref_woitg, string_obj1, ret_ucl_copy_value_trash_wgeys, (size_t )ret_ucl_object_todouble_wgwaf, 1);
    if (ret_ucl_object_insert_key_merged_eowpt == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    ucl_object_t *string_obj2 = ucl_object_fromstring_common(str, len, flags);
    if (!string_obj2) {
        goto cleanup;
    }

    if (!ucl_object_insert_key(obj, string_obj2, "key2", 4, true)) {
        goto cleanup;
    }

    ucl_object_t *string_obj3 = ucl_object_fromstring_common(str, len, flags);
    if (!string_obj3) {
        goto cleanup;
    }

    if (!ucl_object_insert_key(obj, string_obj3, "key3", 4, true)) {
        goto cleanup;
    }

    write_dummy_file(Data, Size);

    FILE *fp = fopen("./dummy_file", "r");
    if (!fp) {
        goto cleanup;
    }

    struct ucl_emitter_functions *emitter_funcs = ucl_object_emit_file_funcs(fp);
    if (!emitter_funcs) {
        fclose(fp);
        goto cleanup;
    }

    struct ucl_emitter_context *ctx = ucl_object_emit_streamline_new(obj, UCL_EMIT_JSON, emitter_funcs);
    if (!ctx) {
        fclose(fp);
        goto cleanup;
    }

    ucl_object_emit_streamline_new(obj, UCL_EMIT_JSON, emitter_funcs);
    ucl_object_emit_streamline_new(obj, UCL_EMIT_JSON, emitter_funcs);
    ucl_object_emit_streamline_new(obj, UCL_EMIT_JSON, emitter_funcs);

    ucl_object_emit_streamline_start_container(ctx, obj);

    fclose(fp);

cleanup:
    ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
