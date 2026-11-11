// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_inner at tree_data_new.c:446:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_load_module at context.c:239:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_dup_single at tree_data.c:2510:1 in tree_data.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_merge_siblings at tree_data.c:2850:1 in tree_data.h
// lyd_diff_siblings at diff.c:1435:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <tree_data.h>
#include <context.h>

static struct lyd_node *create_dummy_lyd_node(struct ly_ctx *ctx, const struct lys_module *module) {
    struct lyd_node *node = NULL;
    if (lyd_new_inner(NULL, module, "dummy", 0, &node) != LY_SUCCESS) {
        return NULL;
    }
    return node;
}

static struct ly_ctx *create_dummy_ly_ctx() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static const struct lys_module *create_dummy_lys_module(struct ly_ctx *ctx) {
    const struct lys_module *module = ly_ctx_load_module(ctx, "ietf-yang-library", NULL, NULL);
    return module;
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    struct ly_ctx *trg_ctx = create_dummy_ly_ctx();
    if (!trg_ctx) {
        return 0;
    }
    
    const struct lys_module *module = create_dummy_lys_module(trg_ctx);
    if (!module) {
        ly_ctx_destroy(trg_ctx);
        return 0;
    }

    struct lyd_node *node = create_dummy_lyd_node(trg_ctx, module);
    struct lyd_node *parent = create_dummy_lyd_node(trg_ctx, module);
    struct lyd_node *dup = NULL;
    char *value = NULL;
    
    if (Size > 0) {
        value = malloc(Size + 1);
        if (!value) {
            goto cleanup;
        }
        memcpy(value, Data, Size);
        value[Size] = '\0';
    }

    if (node && parent) {
        lyd_dup_siblings(node, parent, 0, &dup);
        lyd_dup_single(node, parent, 0, &dup);
        lyd_dup_siblings_to_ctx(node, trg_ctx, parent, 0, &dup);
        lyd_new_term(parent, module, "dummy_name", value, 0, &dup);
        lyd_merge_siblings(&node, parent, 0);
        lyd_diff_siblings(node, parent, 0, &dup);
    }

cleanup:
    lyd_free_tree(node);
    lyd_free_tree(parent);
    ly_ctx_destroy(trg_ctx);
    free(value);
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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    