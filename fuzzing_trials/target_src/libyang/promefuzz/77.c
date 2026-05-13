// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_compare_meta at tree_data.c:1892:1 in tree_data.h
// lyd_new_meta at tree_data_new.c:789:1 in tree_data.h
// lyd_find_meta at tree_data.c:3138:1 in tree_data.h
// lyd_meta_is_internal at tree_data_common.c:1053:1 in tree_data.h
// lyd_free_meta_single at tree_data_free.c:75:1 in tree_data.h
// lyd_free_meta_siblings at tree_data_free.c:81:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tree_data.h"
#include "libyang.h"  // Include the libyang header for context functions

static struct lyd_meta *create_dummy_meta() {
    return NULL;  // Return NULL as we cannot allocate incomplete types
}

static void free_dummy_meta(struct lyd_meta *meta) {
    // No operation needed since we are not allocating memory for lyd_meta
}

static struct lys_module *create_dummy_module(struct ly_ctx *ctx) {
    struct lys_module *module = (struct lys_module *)malloc(sizeof(struct lys_module));
    if (!module) {
        return NULL;
    }
    memset(module, 0, sizeof(struct lys_module));
    module->ctx = ctx;  // Assign the context to avoid use-after-free errors
    return module;
}

static void free_dummy_module(struct lys_module *module) {
    free(module);
}

static struct lyd_node *create_dummy_node() {
    struct lyd_node *node = (struct lyd_node *)malloc(sizeof(struct lyd_node));
    if (!node) {
        return NULL;
    }
    memset(node, 0, sizeof(struct lyd_node));
    return node;
}

static void free_dummy_node(struct lyd_node *node) {
    free(node);
}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct lyd_meta *meta1 = create_dummy_meta();
    struct lyd_meta *meta2 = create_dummy_meta();
    struct ly_ctx *ctx = NULL;
    struct lyd_meta *meta_out = NULL;
    
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    struct lys_module *module = create_dummy_module(ctx);
    struct lyd_node *parent = create_dummy_node();

    if (!module || !parent) {
        free_dummy_module(module);
        free_dummy_node(parent);
        ly_ctx_destroy(ctx);
        return 0;
    }

    // Fuzz lyd_compare_meta
    lyd_compare_meta(meta1, meta2);

    // Fuzz lyd_new_meta
    lyd_new_meta(ctx, parent, module, "dummy_name", "dummy_value", 0, &meta_out);

    // Fuzz lyd_find_meta
    lyd_find_meta(meta1, module, "dummy_name");

    // Fuzz lyd_meta_is_internal
    lyd_meta_is_internal(meta1);

    // Fuzz lyd_free_meta_single
    lyd_free_meta_single(meta1);

    // Fuzz lyd_free_meta_siblings
    lyd_free_meta_siblings(meta2);

    free_dummy_module(module);
    free_dummy_node(parent);
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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    