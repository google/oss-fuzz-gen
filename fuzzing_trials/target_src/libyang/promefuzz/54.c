// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_insert_after at tree_data.c:1164:1 in tree_data.h
// lyd_unlink_siblings at tree_data.c:1266:1 in tree_data.h
// lyd_insert_sibling at tree_data.c:1114:1 in tree_data.h
// lyd_insert_before at tree_data.c:1140:1 in tree_data.h
// lyd_unlink_tree at tree_data.c:1293:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tree_data.h"

static struct lys_module dummy_module = {
    .name = "dummy-module",
    .ns = "urn:dummy-module",
    .prefix = "dm"
};

static struct lysc_node dummy_schema_node = {
    .nodetype = 0,
    .module = &dummy_module,
    .name = "dummy-node"
};

static struct lyd_node *create_dummy_node() {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (node) {
        memset(node, 0, sizeof(struct lyd_node));
        node->schema = &dummy_schema_node;
        node->prev = node; // Initialize prev to point to itself
        node->hash = 1; // Ensure hash is non-zero
    }
    return node;
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct lyd_node *sibling = create_dummy_node();
    struct lyd_node *node = create_dummy_node();
    struct lyd_node *first = NULL;

    if (!sibling || !node) {
        free(sibling);
        free(node);
        return 0;
    }

    // Fuzz lyd_insert_after
    lyd_insert_after(sibling, node);

    // Fuzz lyd_unlink_siblings
    lyd_unlink_siblings(sibling);

    // Fuzz lyd_insert_sibling
    lyd_insert_sibling(sibling, node, &first);

    // Fuzz lyd_insert_before
    lyd_insert_before(sibling, node);

    // Fuzz lyd_unlink_tree
    lyd_unlink_tree(sibling);

    // Fuzz lyd_dup_siblings
    struct lyd_node *dup = NULL;
    lyd_dup_siblings(node, NULL, 0, &dup);
    free(dup);

    // Cleanup
    free(sibling);
    free(node);

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

        LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    