#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/parser_data.h"

static int fuzz_ly_ctx_compiled_size(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    int size = ly_ctx_compiled_size(ctx);
    if (size == -1) {
        // Handle error if needed
    }

    ly_ctx_destroy(ctx);
    return 0;
}

static int fuzz_ly_ctx_get_yanglib_data(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    err = ly_ctx_get_yanglib_data(ctx, &root, "%u", 0);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    lyd_free_all(root);
    ly_ctx_destroy(ctx);
    return 0;
}

static int fuzz_ly_ctx_new_ylmem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    char *data = (char *)malloc(Size + 1);
    if (!data) {
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    LY_ERR err = ly_ctx_new_ylmem(NULL, data, LYD_XML, 0, &ctx);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }

    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

static int fuzz_lyd_validate_all(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL, *diff = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    err = lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);
    if (err == LY_SUCCESS) {
        err = lyd_validate_all(&tree, ctx, 0, &diff);
        if (err != LY_SUCCESS) {
            // Handle error if needed
        }
        lyd_free_all(diff);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lyd_parse_data_mem to lyd_validate_all
    // Ensure dataflow is valid (i.e., non-null)
    if (!ctx) {
    	return 0;
    }
    LY_ERR ret_ly_ctx_compile_zkxcj = ly_ctx_compile(ctx);
    // Ensure dataflow is valid (i.e., non-null)
    if (!ctx) {
    	return 0;
    }
    uint32_t ret_ly_ctx_internal_modules_count_lcath = ly_ctx_internal_modules_count(ctx);
    if (ret_ly_ctx_internal_modules_count_lcath < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ly_ctx_internal_modules_count to lyd_compare_siblings
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    struct lyd_node* ret_lyd_child_no_keys_qesqw = lyd_child_no_keys(tree);
    if (ret_lyd_child_no_keys_qesqw == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_qesqw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from lyd_child_no_keys to lyd_dup_single_to_ctx using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_qesqw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ctx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_qesqw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function lyd_dup_single_to_ctx with lyd_dup_siblings_to_ctx

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from lyd_child_no_keys to lyd_dup_single using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_qesqw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_qesqw) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_qesqw) {
    	return 0;
    }
    LY_ERR ret_lyd_dup_single_cucwd = lyd_dup_single(ret_lyd_child_no_keys_qesqw, ret_lyd_child_no_keys_qesqw, ret_ly_ctx_internal_modules_count_lcath, &ret_lyd_child_no_keys_qesqw);
    // End mutation: Producer.SPLICE_MUTATOR
    
    LY_ERR ret_lyd_dup_single_to_ctx_npntn = lyd_dup_siblings_to_ctx(ret_lyd_child_no_keys_qesqw, ctx, ret_lyd_child_no_keys_qesqw, ret_ly_ctx_internal_modules_count_lcath, &tree);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // End mutation: Producer.SPLICE_MUTATOR
    
    LY_ERR ret_lyd_compare_siblings_wprnh = lyd_compare_siblings(ret_lyd_child_no_keys_qesqw, tree, ret_ly_ctx_internal_modules_count_lcath);
    // End mutation: Producer.APPEND_MUTATOR
    
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function lyd_unlink_tree with lyd_unlink_siblings
    LY_ERR ret_lyd_unlink_tree_fagfw = lyd_unlink_siblings(tree);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ctx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lyd_unlink_siblings to lyd_new_list2
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    uint32_t ret_lyd_list_pos_lrqio = lyd_list_pos(tree);
    if (ret_lyd_list_pos_lrqio < 0){
    	return 0;
    }
    struct lys_module bzlsiyyh;
    memset(&bzlsiyyh, 0, sizeof(bzlsiyyh));
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    LY_ERR ret_lyd_new_list2_kpoud = lyd_new_list2(tree, &bzlsiyyh, NULL, (const char *)"r", ret_lyd_list_pos_lrqio, &tree);
    // End mutation: Producer.APPEND_MUTATOR
    
    LY_ERR ret_lyd_validate_all_rllvz = lyd_validate_all(&tree, ctx, ret_ly_ctx_internal_modules_count_lcath, &tree);
    // End mutation: Producer.APPEND_MUTATOR
    
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

static int fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    err = lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);
    if (err != LY_SUCCESS) {
        // Handle error if needed
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lyd_parse_data_mem to lyd_trim_xpath
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    LY_ERR ret_lyd_trim_xpath_vhmcn = lyd_trim_xpath(&tree, (const char *)"w", NULL);
    // End mutation: Producer.APPEND_MUTATOR
    
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

static int fuzz_ly_ctx_new_yldata(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *tree = NULL;

    LY_ERR err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        return 0;
    }

    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data, Data, Size);
    data[Size] = '\0';

    err = lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);
    if (err == LY_SUCCESS) {
        err = ly_ctx_new_yldata(NULL, tree, 0, &ctx);
        if (err != LY_SUCCESS) {
            // Handle error if needed
        }
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lyd_parse_data_mem to lyd_validate_module_final
    // Ensure dataflow is valid (i.e., non-null)
    if (!ctx) {
    	return 0;
    }
    uint32_t ret_ly_ctx_internal_modules_count_owotm = ly_ctx_internal_modules_count(ctx);
    if (ret_ly_ctx_internal_modules_count_owotm < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tree) {
    	return 0;
    }
    LY_ERR ret_lyd_validate_module_final_wplmw = lyd_validate_module_final(tree, NULL, ret_ly_ctx_internal_modules_count_owotm);
    // End mutation: Producer.APPEND_MUTATOR
    
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    fuzz_ly_ctx_compiled_size(Data, Size);
    fuzz_ly_ctx_get_yanglib_data(Data, Size);
    fuzz_ly_ctx_new_ylmem(Data, Size);
    fuzz_lyd_validate_all(Data, Size);
    fuzz_lyd_parse_data_mem(Data, Size);
    fuzz_ly_ctx_new_yldata(Data, Size);
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
