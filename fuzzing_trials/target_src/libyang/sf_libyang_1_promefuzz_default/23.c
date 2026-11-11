// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_dup_single at tree_data.c:2510:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_merge_siblings at tree_data.c:2850:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_diff_siblings at diff.c:1435:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>
#include <tree_data.h>

static struct lyd_node *create_dummy_node(struct ly_ctx *ctx) {
    struct lyd_node *node = NULL;
    if (lyd_new_path(NULL, ctx, "/example-module:container", NULL, 0, &node) != LY_SUCCESS) {
        return NULL;
    }
    return node;
}

static struct ly_ctx *create_dummy_context(void) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = create_dummy_context();
    if (!ctx) {
        return 0;
    }

    struct lyd_node *node = create_dummy_node(ctx);
    struct lyd_node *parent = create_dummy_node(ctx);
    struct ly_ctx *trg_ctx = create_dummy_context();
    struct lyd_node *dup = NULL;
    uint32_t options = Data[0];

    // Test lyd_dup_siblings
    lyd_dup_siblings(node, parent, options, &dup);
    if (dup) {
        lyd_free_tree(dup);
    }

    // Test lyd_dup_single
    lyd_dup_single(node, parent, options, &dup);
    if (dup) {
        lyd_free_tree(dup);
    }

    // Test lyd_dup_siblings_to_ctx
    lyd_dup_siblings_to_ctx(node, trg_ctx, parent, options, &dup);
    if (dup) {
        lyd_free_tree(dup);
    }

    // Prepare data for lyd_new_term
    char *value = (char *)malloc(Size + 1);
    if (value) {
        memcpy(value, Data, Size);
        value[Size] = '\0';
        struct lys_module *module = NULL; // Dummy module
        struct lyd_node *new_node = NULL;

        // Test lyd_new_term
        lyd_new_term(parent, module, "dummy_name", value, options, &new_node);
        if (new_node) {
            lyd_free_tree(new_node);
        }

        free(value);
    }

    // Test lyd_merge_siblings
    struct lyd_node *target = create_dummy_node(ctx);
    lyd_merge_siblings(&target, node, (uint16_t)options);
    if (target) {
        lyd_free_tree(target);
    }

    // Test lyd_diff_siblings
    struct lyd_node *diff = NULL;
    lyd_diff_siblings(node, parent, (uint16_t)options, &diff);
    if (diff) {
        lyd_free_tree(diff);
    }

    lyd_free_tree(node);
    lyd_free_tree(parent);
    ly_ctx_destroy(trg_ctx);
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    