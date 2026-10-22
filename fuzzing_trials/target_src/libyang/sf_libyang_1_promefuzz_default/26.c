// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_load_module at context.c:239:1 in context.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_list3 at tree_data_new.c:632:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_dup_siblings_to_ctx at tree_data.c:2547:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_list at tree_data_new.c:528:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libyang.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static struct lys_module *load_module(struct ly_ctx *ctx, const char *module_name) {
    const char *features[] = {NULL};
    return ly_ctx_load_module(ctx, module_name, NULL, features);
}

static struct lyd_node *create_data_tree(struct ly_ctx *ctx, const char *module_name) {
    struct lys_module *module = load_module(ctx, module_name);
    if (!module) {
        return NULL;
    }

    struct lyd_node *root = NULL;
    if (lyd_new_path(NULL, ctx, "/dummy-module:container", NULL, 0, &root) != LY_SUCCESS) {
        return NULL;
    }
    return root;
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return 0;
    }

    struct lyd_node *node = create_data_tree(ctx, "dummy-module");
    if (!node) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *dup = NULL;
    lyd_dup_siblings(node, NULL, 0, &dup);
    lyd_free_all(dup);

    const struct lys_module *module = load_module(ctx, "dummy-module");
    if (module) {
        struct lyd_node *list_node = NULL;
        lyd_new_list3(NULL, module, "list-node", NULL, NULL, 0, &list_node);
        lyd_free_all(list_node);
    }

    struct ly_ctx *trg_ctx = create_context();
    if (trg_ctx) {
        struct lyd_node *dup_to_ctx = NULL;
        lyd_dup_siblings_to_ctx(node, trg_ctx, NULL, 0, &dup_to_ctx);
        lyd_free_all(dup_to_ctx);
        ly_ctx_destroy(trg_ctx);
    }

    struct lyd_node *path_node = NULL;
    lyd_new_path(NULL, ctx, "/dummy-module:path", "value", 0, &path_node);
    lyd_free_all(path_node);

    struct lyd_node *term_node = NULL;
    lyd_new_term(NULL, module, "term-node", "value", 0, &term_node);
    lyd_free_all(term_node);

    struct lyd_node *list_node_var = NULL;
    lyd_new_list(NULL, module, "list-node", 0, &list_node_var, "key1", "key2");
    lyd_free_all(list_node_var);

    lyd_free_all(node);
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    