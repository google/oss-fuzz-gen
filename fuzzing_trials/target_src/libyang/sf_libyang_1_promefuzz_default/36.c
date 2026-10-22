// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_dup_single at tree_data.c:2510:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_merge_siblings at tree_data.c:2850:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_insert_after at tree_data.c:1164:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_leafref_link_node_tree at tree_data.c:3904:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"

static struct lys_module *create_dummy_module(struct ly_ctx *ctx) {
    struct lys_module *module = (struct lys_module *)malloc(sizeof(struct lys_module));
    if (!module) {
        return NULL;
    }
    memset(module, 0, sizeof *module);
    module->ctx = ctx;
    module->name = "dummy_module";
    return module;
}

static struct lyd_node *create_dummy_node(struct lys_module *module) {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof *node);
    struct lysc_node *schema = (struct lysc_node *)malloc(sizeof(struct lysc_node));
    if (!schema) {
        free(node);
        return NULL;
    }
    memset(schema, 0, sizeof *schema);
    schema->module = module;
    node->schema = schema;
    return node;
}

static void free_dummy_node(struct lyd_node *node) {
    if (node) {
        free((void *)node->schema);
        free(node);
    }
}

int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    struct lys_module *module = create_dummy_module(ctx);
    if (!module) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *sibling = create_dummy_node(module);
    struct lyd_node *node = create_dummy_node(module);
    if (!sibling || !node) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Fuzzing lyd_insert_after
    LY_ERR err = lyd_insert_after(sibling, node);
    if (err != LY_SUCCESS && err != LY_EINVAL) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *dup_node = NULL;
    // Fuzzing lyd_dup_siblings_to_ctx
    err = lyd_dup_siblings_to_ctx(sibling, ctx, NULL, 0, &dup_node);
    if (err != LY_SUCCESS && err != LY_EINVAL) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }
    free_dummy_node(dup_node);

    // Fuzzing lyd_leafref_link_node_tree
    err = lyd_leafref_link_node_tree(sibling);
    if (err != LY_SUCCESS && err != LY_EINVAL) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Fuzzing lyd_dup_single
    err = lyd_dup_single(sibling, NULL, 0, &dup_node);
    if (err != LY_SUCCESS && err != LY_EINVAL) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }
    free_dummy_node(dup_node);

    // Fuzzing lyd_new_term
    struct lyd_node *term_node = NULL;
    err = lyd_new_term(NULL, module, "dummy_name", (const char *)Data, 0, &term_node);
    if (err != LY_SUCCESS && err != LY_EINVAL) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }
    free_dummy_node(term_node);

    // Fuzzing lyd_merge_siblings
    err = lyd_merge_siblings(&sibling, node, 0);
    if (err != LY_SUCCESS && err != LY_EINVAL) {
        free_dummy_node(sibling);
        free_dummy_node(node);
        free(module);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Cleanup
    free_dummy_node(sibling);
    free_dummy_node(node);
    free(module);
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

        LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    