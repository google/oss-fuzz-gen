// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_get_module_latest at context.c:972:1 in context.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_implicit_module at tree_data_new.c:2050:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_validate_all at validation.c:2202:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_implicit_tree at tree_data_new.c:1971:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_validate_module_final at validation.c:2229:1 in parser_data.h
// lyd_dup_single_to_ctx at tree_data.c:2522:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "parser_data.h"
#include "tree_data.h"
#include "libyang.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        fprintf(stderr, "Failed to create libyang context.\n");
        return NULL;
    }
    return ctx;
}

static struct lys_module *load_module(struct ly_ctx *ctx, const char *name) {
    if (!ctx) {
        return NULL;
    }
    struct lys_module *mod = ly_ctx_get_module_latest(ctx, name);
    if (!mod) {
        fprintf(stderr, "Failed to load module: %s\n", name);
    }
    return mod;
}

static struct lyd_node *create_dummy_data_tree(struct ly_ctx *ctx) {
    if (!ctx) {
        return NULL;
    }
    struct lyd_node *tree = NULL;
    LY_ERR err = lyd_new_path(NULL, ctx, "/module:container", NULL, 0, &tree);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create dummy data tree.\n");
        return NULL;
    }
    return tree;
}

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return 0;
    }

    struct lys_module *module = load_module(ctx, "module");
    if (!module) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *tree = create_dummy_data_tree(ctx);
    if (!tree) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *diff = NULL;
    uint32_t options = 0;

    // Fuzz target: lyd_new_implicit_all
    lyd_new_implicit_all(&tree, ctx, options, &diff);
    lyd_free_all(diff);

    // Fuzz target: lyd_new_implicit_module
    lyd_new_implicit_module(&tree, module, options, &diff);
    lyd_free_all(diff);

    // Fuzz target: lyd_validate_all
    lyd_validate_all(&tree, ctx, options, &diff);
    lyd_free_all(diff);

    // Fuzz target: lyd_new_implicit_tree
    lyd_new_implicit_tree(tree, options, &diff);
    lyd_free_all(diff);

    // Fuzz target: lyd_validate_module_final
    lyd_validate_module_final(tree, module, options);

    // Fuzz target: lyd_dup_single_to_ctx
    struct lyd_node *dup = NULL;
    lyd_dup_single_to_ctx(tree, ctx, NULL, options, &dup);
    lyd_free_all(dup);

    lyd_free_all(tree);
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

        LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    