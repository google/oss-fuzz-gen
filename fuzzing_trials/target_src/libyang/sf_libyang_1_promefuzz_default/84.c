// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_insert_after at tree_data.c:1164:1 in tree_data.h
// lyd_leafref_link_node_tree at tree_data.c:3904:1 in tree_data.h
// lyd_merge_siblings at tree_data.c:2850:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tree_data.h"

static void fuzz_lyd_dup_siblings_to_ctx(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;
    struct ly_ctx *trg_ctx = NULL;
    struct lyd_node *parent = NULL;
    struct lyd_node *dup = NULL;
    uint32_t options = 0;

    // Call the function
    lyd_dup_siblings_to_ctx(node, trg_ctx, parent, options, &dup);

    // Cleanup
    if (dup) {
        lyd_free_tree(dup);
    }
}

static void fuzz_lyd_insert_after(const uint8_t *Data, size_t Size) {
    struct lyd_node *sibling = NULL;
    struct lyd_node *node = NULL;

    // Call the function
    lyd_insert_after(sibling, node);
}

static void fuzz_lyd_leafref_link_node_tree(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;

    // Call the function
    lyd_leafref_link_node_tree(tree);
}

static void fuzz_lyd_merge_siblings(const uint8_t *Data, size_t Size) {
    struct lyd_node *target = NULL;
    struct lyd_node *source = NULL;
    uint16_t options = 0;

    // Call the function
    lyd_merge_siblings(&target, source, options);

    // Cleanup
    if (target) {
        lyd_free_tree(target);
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct lys_module module;
    const char *name = "dummy_name";
    char *value = (char *)malloc(Size + 1);
    struct lyd_node *node = NULL;
    uint32_t options = 0;

    if (!value) {
        return;
    }

    // Prepare value
    memcpy(value, Data, Size);
    value[Size] = '\0';

    // Initialize module
    module.name = "dummy_module";

    // Call the function
    lyd_new_term(parent, &module, name, value, options, &node);

    // Cleanup
    free(value);
    if (node) {
        lyd_free_tree(node);
    }
}

static void fuzz_lyd_new_implicit_all(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = NULL;
    struct ly_ctx *ctx = NULL;
    struct lyd_node *diff = NULL;
    uint32_t implicit_options = 0;

    // Call the function
    lyd_new_implicit_all(&tree, ctx, implicit_options, &diff);

    // Cleanup
    if (diff) {
        lyd_free_tree(diff);
    }
}

int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
    fuzz_lyd_dup_siblings_to_ctx(Data, Size);
    fuzz_lyd_insert_after(Data, Size);
    fuzz_lyd_leafref_link_node_tree(Data, Size);
    fuzz_lyd_merge_siblings(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_new_implicit_all(Data, Size);

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

        LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    