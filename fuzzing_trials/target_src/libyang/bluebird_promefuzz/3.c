#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/libyang/src/parser_data.h"
#include "/src/libyang/src/tree_data.h"
#include "/src/libyang/src/context.h"
#include "/src/libyang/src/in.h"
#include "/src/libyang/src/set.h"

static void fuzz_lyd_any_value_str(const struct lyd_node *node) {
    char *value_str = NULL;
    LY_ERR err = lyd_any_value_str(node, LYD_XML, &value_str);
    if (err == LY_SUCCESS) {
        free(value_str);
    }
}

static void fuzz_lyd_parse_op(const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return;
    }
    
    struct ly_in *in;
    struct lyd_node *tree = NULL, *op = NULL;
    // Ensure the input is null-terminated
    char *data = strndup((const char *)Data, Size);
    ly_in_new_memory(data, &in);

    lyd_parse_op(ctx, NULL, in, LYD_XML, LYD_TYPE_RPC_NETCONF, 0, &tree, &op);

    lyd_free_all(tree);
    lyd_free_all(op);
    ly_in_free(in, 0);
    free(data);
}

static void fuzz_lyd_validate_op(struct lyd_node *op_tree) {
    struct lyd_node *diff = NULL;
    lyd_validate_op(op_tree, NULL, LYD_TYPE_RPC_YANG, &diff);
    lyd_free_all(diff);
}

static void fuzz_lyd_find_xpath3(const struct lyd_node *tree, const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return;
    }
    
    struct ly_set *set = NULL;
    char *xpath = strndup((const char *)Data, Size);

    lyd_find_xpath3(NULL, tree, xpath, LY_VALUE_JSON, NULL, NULL, &set);

    ly_set_free(set, NULL);
    free(xpath);
}

static void fuzz_lyd_parse_data_mem(const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return;
    }
    
    struct lyd_node *tree = NULL;
    char *data = strndup((const char *)Data, Size);

    lyd_parse_data_mem(ctx, data, LYD_XML, 0, 0, &tree);

    lyd_free_all(tree);
    free(data);
}

static void fuzz_lyd_compare_single(const struct lyd_node *node1, const struct lyd_node *node2) {
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function lyd_compare_single with lyd_compare_siblings
    lyd_compare_siblings(node1, node2, 0);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node1 = NULL, *node2 = NULL;

    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    // Fuzzing individual functions
    fuzz_lyd_any_value_str(node1);
    fuzz_lyd_parse_op(ctx, Data, Size);
    fuzz_lyd_validate_op(node1);
    fuzz_lyd_find_xpath3(node1, Data, Size);
    fuzz_lyd_parse_data_mem(ctx, Data, Size);
    fuzz_lyd_compare_single(node1, node2);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
