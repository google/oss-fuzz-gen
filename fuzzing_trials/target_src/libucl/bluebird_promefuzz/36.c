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

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
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

    ucl_object_t *string_obj2 = ucl_object_fromstring_common(str, len, flags);
    if (!string_obj2) {
        goto cleanup;
    }

    if (!ucl_object_insert_key(obj, string_obj2, "key2", 4, true)) {
        goto cleanup;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ucl_object_fromstring_common to ucl_object_replace_key
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    ucl_object_t* ret_ucl_object_copy_rfkyz = ucl_object_copy(obj);
    if (ret_ucl_object_copy_rfkyz == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!string_obj2) {
    	return 0;
    }
    char* ret_ucl_copy_key_trash_diewz = ucl_copy_key_trash(string_obj2);
    if (ret_ucl_copy_key_trash_diewz == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    double ret_ucl_object_todouble_ilysl = ucl_object_todouble(obj);
    if (ret_ucl_object_todouble_ilysl < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_object_copy_rfkyz) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!string_obj1) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_ucl_copy_key_trash_diewz) {
    	return 0;
    }
    bool ret_ucl_object_replace_key_vlugw = ucl_object_replace_key(ret_ucl_object_copy_rfkyz, string_obj1, ret_ucl_copy_key_trash_diewz, (size_t )ret_ucl_object_todouble_ilysl, 1);
    if (ret_ucl_object_replace_key_vlugw == 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
