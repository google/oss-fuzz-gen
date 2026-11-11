// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_unlink_tree at tree_data.c:1293:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_dup_single at tree_data.c:2510:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_any at tree_data_new.c:749:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>

static struct lyd_node *create_dummy_node(const struct lysc_node *schema, struct ly_ctx *ctx) {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(*node));
    node->schema = schema;
    node->parent = NULL;
    node->next = NULL;  // Correctly initialize as NULL
    node->prev = node;  // Correctly initialize as self-referential
    return node;
}

static struct lys_module *create_dummy_module(const char *name, struct ly_ctx *ctx) {
    struct lys_module *module = (struct lys_module *)malloc(sizeof(struct lys_module));
    if (!module) {
        return NULL;
    }
    memset(module, 0, sizeof(*module));
    module->name = name;
    module->ctx = ctx; // Set the context
    return module;
}

static struct lysc_node *create_dummy_schema_node(struct lys_module *module) {
    struct lysc_node *schema_node = (struct lysc_node *)malloc(sizeof(struct lysc_node));
    if (!schema_node) {
        return NULL;
    }
    memset(schema_node, 0, sizeof(*schema_node));
    schema_node->module = module;
    return schema_node;
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    uint32_t options = Data[0];
    const char *dummy_name = "dummy_name";
    char *value = (char *)malloc(Size + 1);
    if (!value) {
        return 0;
    }
    memcpy(value, Data, Size);
    value[Size] = '\0';

    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        free(value);
        return 0;
    }

    struct lys_module *dummy_module = create_dummy_module("dummy", ctx);
    if (!dummy_module) {
        free(value);
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lysc_node *dummy_schema_node = create_dummy_schema_node(dummy_module);
    if (!dummy_schema_node) {
        free(dummy_module);
        free(value);
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *parent = create_dummy_node(dummy_schema_node, ctx);
    struct lyd_node *node = create_dummy_node(dummy_schema_node, ctx);
    struct lyd_node *dup = NULL;

    // Fuzz lyd_dup_siblings
    lyd_dup_siblings(node, parent, options, &dup);
    if (dup) {
        // Clean up duplicated nodes
        lyd_free_all(dup);
    }

    // Fuzz lyd_dup_single
    lyd_dup_single(node, parent, options, &dup);
    if (dup) {
        // Clean up duplicated node
        lyd_free_all(dup);
    }

    // Fuzz lyd_new_any
    struct lyd_node *new_any_node = NULL;
    lyd_new_any(parent, dummy_module, dummy_name, NULL, value, 0, options, &new_any_node);
    if (new_any_node) {
        lyd_free_all(new_any_node);
    }

    // Fuzz lyd_unlink_tree
    if (node) {
        lyd_unlink_tree(node);
    }

    // Fuzz lyd_new_term
    struct lyd_node *new_term_node = NULL;
    lyd_new_term(parent, dummy_module, dummy_name, value, options, &new_term_node);
    if (new_term_node) {
        lyd_free_all(new_term_node);
    }

    // Fuzz lyd_insert_child
    lyd_insert_child(parent, node);

    // Clean up
    if (parent && parent != node) {
        lyd_free_all(parent);
    }
    if (node) {
        lyd_free_all(node);
    }
    free(dummy_schema_node);
    free(dummy_module);
    free(value);
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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    