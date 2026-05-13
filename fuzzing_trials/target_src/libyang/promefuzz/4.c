// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_new_implicit_tree at tree_data_new.c:1971:1 in tree_data.h
// lyd_dup_single_to_ctx at tree_data.c:2522:1 in tree_data.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tree_data.h"

static struct lyd_node *create_dummy_lyd_node(const struct lysc_node *schema) {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    node->prev = node; // Ensure 'prev' is never NULL
    node->schema = schema; // Assign schema to avoid null dereference
    return node;
}

static void cleanup_lyd_node(struct lyd_node *node) {
    if (node) {
        free(node);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a dummy schema node to avoid null dereference
    struct lysc_node dummy_schema;
    memset(&dummy_schema, 0, sizeof(dummy_schema));

    struct lyd_node *parent = create_dummy_lyd_node(&dummy_schema);
    struct lyd_node *node = create_dummy_lyd_node(&dummy_schema);
    if (!parent || !node) {
        cleanup_lyd_node(parent);
        cleanup_lyd_node(node);
        return 0;
    }

    LY_ERR err;

    // Fuzz lyd_insert_child
    err = lyd_insert_child(parent, node);
    if (err != LY_SUCCESS) {
        cleanup_lyd_node(parent);
        cleanup_lyd_node(node);
        return 0;
    }

    struct lyd_node *tree = create_dummy_lyd_node(&dummy_schema);
    struct lyd_node *diff = NULL;
    uint32_t implicit_options = *((uint32_t *)Data);

    // Fuzz lyd_new_implicit_all
    err = lyd_new_implicit_all(&tree, NULL, implicit_options, &diff);
    if (err != LY_SUCCESS) {
        cleanup_lyd_node(tree);
        cleanup_lyd_node(diff);
        cleanup_lyd_node(parent);
        cleanup_lyd_node(node);
        return 0;
    }

    // Fuzz lyd_new_implicit_tree
    err = lyd_new_implicit_tree(tree, implicit_options, &diff);
    if (err != LY_SUCCESS) {
        cleanup_lyd_node(tree);
        cleanup_lyd_node(diff);
        cleanup_lyd_node(parent);
        cleanup_lyd_node(node);
        return 0;
    }

    uint32_t options = *((uint32_t *)(Data + sizeof(uint32_t)));
    struct lyd_node *dup = NULL;

    // Fuzz lyd_dup_single_to_ctx
    err = lyd_dup_single_to_ctx(node, NULL, parent, options, &dup);
    if (err != LY_SUCCESS) {
        cleanup_lyd_node(dup);
        cleanup_lyd_node(tree);
        cleanup_lyd_node(diff);
        cleanup_lyd_node(parent);
        cleanup_lyd_node(node);
        return 0;
    }

    // Fuzz lyd_dup_siblings_to_ctx
    err = lyd_dup_siblings_to_ctx(node, NULL, parent, options, &dup);
    if (err != LY_SUCCESS) {
        cleanup_lyd_node(dup);
        cleanup_lyd_node(tree);
        cleanup_lyd_node(diff);
        cleanup_lyd_node(parent);
        cleanup_lyd_node(node);
        return 0;
    }

    // Cleanup
    cleanup_lyd_node(dup);
    cleanup_lyd_node(tree);
    cleanup_lyd_node(diff);
    cleanup_lyd_node(parent);
    cleanup_lyd_node(node);

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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    