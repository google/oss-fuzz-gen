// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lys_parse_mem at tree_schema.c:2872:1 in parser_schema.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_eval_xpath3 at tree_data.c:3463:1 in tree_data.h
// lyd_trim_xpath at tree_data.c:3581:1 in tree_data.h
// lyd_validate_module at validation.c:2217:1 in parser_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parser_data.h"
#include "tree_data.h"
#include "libyang.h"

// Helper function to initialize a lys_module
static struct lys_module *initialize_lys_module(struct ly_ctx *ctx, const char *yang_module) {
    struct lys_module *module = NULL;
    if (lys_parse_mem(ctx, yang_module, LYS_IN_YANG, &module) != LY_SUCCESS) {
        return NULL;
    }
    return module;
}

int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    // Initialize context
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    // Dummy YANG module
    const char *yang_module = "module test-module {namespace \"urn:test\"; prefix tm; container test-node {}}";
    struct lys_module *module = initialize_lys_module(ctx, yang_module);
    if (!module) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Initialize data nodes
    struct lyd_node *parent_node = NULL;
    if (lyd_new_inner(NULL, module, "test-node", 0, &parent_node) != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *node = NULL;
    if (lyd_new_inner(parent_node, module, "test-node", 0, &node) != LY_SUCCESS) {
        lyd_free_all(parent_node);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Test lyd_dup_siblings
    struct lyd_node *dup_node = NULL;
    lyd_dup_siblings(node, parent_node, 0, &dup_node);

    // Test lyd_new_list3
    const void *key_values[] = { "key1", "key2" };
    uint32_t value_sizes_bits[] = { 8, 8 };
    struct lyd_node *list_node = NULL;
    lyd_new_list3(parent_node, module, "list-node", key_values, value_sizes_bits, 0, &list_node);

    // Test lyd_eval_xpath3
    ly_bool result;
    if (node && module) {
        lyd_eval_xpath3(node, module, "/test-module:test-node", 0, NULL, NULL, &result);
    }

    // Test lyd_trim_xpath
    const char *xpath = "/test-module:test-node";
    lyd_trim_xpath(&node, xpath, NULL);

    // Test lyd_validate_module
    struct lyd_node *diff = NULL;
    lyd_validate_module(&node, module, 0, &diff);

    // Test lyd_new_term
    char *value = (char *)malloc(Size + 1);
    if (value) {
        memcpy(value, Data, Size);
        value[Size] = '\0';
        struct lyd_node *term_node = NULL;
        lyd_new_term(parent_node, module, "term-node", value, 0, &term_node);
        free(value);
    }

    // Cleanup
    lyd_free_all(dup_node);
    lyd_free_all(list_node);
    lyd_free_all(diff);
    lyd_free_all(node);
    lyd_free_all(parent_node);
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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    