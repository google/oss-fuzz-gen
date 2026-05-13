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


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ly_ctx_get_yanglib_data to lyd_merge_tree
    // Ensure dataflow is valid (i.e., non-null)
    if (!root) {
    	return 0;
    }
    struct lyd_node* ret_lyd_child_no_keys_ehxed = lyd_child_no_keys(root);
    if (ret_lyd_child_no_keys_ehxed == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ctx) {
    	return 0;
    }
    uint32_t ret_ly_ctx_get_options_ramkx = ly_ctx_get_options(ctx);
    if (ret_ly_ctx_get_options_ramkx < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_ehxed) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!root) {
    	return 0;
    }
    LY_ERR ret_lyd_merge_tree_alias = lyd_merge_tree(&ret_lyd_child_no_keys_ehxed, root, (uint16_t )ret_ly_ctx_get_options_ramkx);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lyd_merge_tree to lyd_diff_apply_module
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_ehxed) {
    	return 0;
    }
    struct lyd_node* ret_lyd_child_no_keys_tqefr = lyd_child_no_keys(ret_lyd_child_no_keys_ehxed);
    if (ret_lyd_child_no_keys_tqefr == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_ehxed) {
    	return 0;
    }
    struct lyd_node* ret_lyd_child_no_keys_gewri = lyd_child_no_keys(ret_lyd_child_no_keys_ehxed);
    if (ret_lyd_child_no_keys_gewri == NULL){
    	return 0;
    }
    struct lys_module jpmvkxxa;
    memset(&jpmvkxxa, 0, sizeof(jpmvkxxa));
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_ehxed) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_tqefr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_lyd_child_no_keys_gewri) {
    	return 0;
    }
    LY_ERR ret_lyd_diff_apply_module_cppyu = lyd_diff_apply_module(&ret_lyd_child_no_keys_ehxed, ret_lyd_child_no_keys_tqefr, &jpmvkxxa, NULL, (void *)ret_lyd_child_no_keys_gewri);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    free(data);
    return 0;
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
