// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_insert_child at tree_data.c:1095:1 in tree_data.h
// lyd_leafref_link_node_tree at tree_data.c:3904:1 in tree_data.h
// lyd_insert_after at tree_data.c:1164:1 in tree_data.h
// lyd_diff_apply_all at diff.c:1971:1 in tree_data.h
// lyd_merge_siblings at tree_data.c:2850:1 in tree_data.h
// lyd_insert_before at tree_data.c:1140:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "tree_data.h"

static struct lysc_node *init_lysc_node() {
    struct lysc_node *schema = malloc(sizeof(struct lysc_node));
    if (!schema) {
        return NULL;
    }
    schema->nodetype = 0;
    schema->flags = 0;
    schema->module = NULL;
    schema->parent = NULL;
    schema->next = NULL;
    schema->prev = schema;
    schema->name = NULL;
    schema->dsc = NULL;
    schema->ref = NULL;
    schema->exts = NULL;
    schema->priv = NULL;
    return schema;
}

static struct lyd_node *init_lyd_node() {
    struct lyd_node *node = malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    node->hash = 0;
    node->flags = 0;
    node->schema = init_lysc_node();
    node->parent = NULL;
    node->next = NULL;
    node->prev = node;
    node->meta = NULL;
    node->priv = NULL;
    return node;
}

static void free_lyd_node(struct lyd_node *node) {
    if (node) {
        free((void *)node->schema);
        free(node);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct lyd_node *parent = init_lyd_node();
    struct lyd_node *node = init_lyd_node();
    struct lyd_node *sibling = init_lyd_node();
    struct lyd_node *target = init_lyd_node();
    struct lyd_node *source = init_lyd_node();
    struct lyd_node *diff = init_lyd_node();

    if (!parent || !node || !sibling || !target || !source || !diff) {
        free_lyd_node(parent);
        free_lyd_node(node);
        free_lyd_node(sibling);
        free_lyd_node(target);
        free_lyd_node(source);
        free_lyd_node(diff);
        return 0;
    }

    uint16_t options = Data[0];

    // Ensure the context is valid before calling functions that require it
    if (node->schema && node->schema->module) {
        lyd_insert_child(parent, node);
        lyd_leafref_link_node_tree(node);
        lyd_insert_after(sibling, node);
        lyd_diff_apply_all(&target, diff);
        lyd_merge_siblings(&target, source, options);
        lyd_insert_before(sibling, node);
    }

    free_lyd_node(parent);
    free_lyd_node(node);
    free_lyd_node(sibling);
    free_lyd_node(target);
    free_lyd_node(source);
    free_lyd_node(diff);

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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    