#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stdbool.h"
#include <stdint.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *data_tree = NULL;
    static bool log_initialized = false;

    if (!log_initialized) {
        ly_log_options(0);
        log_initialized = true;
    }

    // Initialize the libyang context
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context\n");
        return 0;
    }

    // Ensure data is not NULL and has a valid length
    if (data == NULL || size == 0) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Convert the input data to a null-terminated string
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Parse the input data as a YANG module
    if (lyd_parse_data_mem(ctx, input_data, LYD_XML, LYD_PARSE_ONLY, 0, &data_tree) != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse data\n");
    }

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from lyd_parse_data_mem to lyd_new_implicit_module
    // Ensure dataflow is valid (i.e., non-null)
    if (!data_tree) {
    	return 0;
    }
    LY_ERR ret_lyd_unlink_siblings_wlaos = lyd_unlink_siblings(data_tree);

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from lyd_unlink_siblings to lyd_eval_xpath4 using the plateau pool
    struct lys_module *module = NULL;
    const char *xpath_expr = "/example-module:container";
    const struct lyxp_var *vars = NULL;
    LY_XPATH_TYPE xptype = LY_XPATH_NODE_SET;
    struct ly_set *set = NULL;
    char *errmsg = NULL;
    long double dbl = 0.0;
    ly_bool bool_val = 0;
    // Ensure dataflow is valid (i.e., non-null)
    if (!data_tree) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!data_tree) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!data_tree) {
    	return 0;
    }
    LY_ERR ret_lyd_eval_xpath4_aedhz = lyd_eval_xpath4(data_tree, data_tree, module, xpath_expr, LY_VALUE_JSON, (void *)data_tree, vars, &xptype, &set, &errmsg, &dbl, &bool_val);
    // End mutation: Producer.SPLICE_MUTATOR
    
    uint32_t ret_ly_ctx_get_modules_hash_tvlwy = ly_ctx_get_modules_hash(NULL);
    if (ret_ly_ctx_get_modules_hash_tvlwy < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!data_tree) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!data_tree) {
    	return 0;
    }
    LY_ERR ret_lyd_new_implicit_module_mryzh = lyd_new_implicit_module(&data_tree, NULL, ret_ly_ctx_get_modules_hash_tvlwy, &data_tree);
    // End mutation: Producer.APPEND_MUTATOR
    
    lyd_free_all(data_tree);
    free(input_data);
    ly_ctx_destroy(ctx);

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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
