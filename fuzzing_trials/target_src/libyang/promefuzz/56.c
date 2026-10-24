// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_dup_single_to_ctx at tree_data.c:2522:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_validate_ext at validation.c:2148:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_path2 at tree_data_new.c:1787:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_validate_all at validation.c:2202:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_data at tree_data.c:195:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "parser_data.h"
#include "tree_data.h"
#include "context.h"
#include "in.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static struct lyd_node *create_dummy_tree() {
    // Create a dummy tree node for testing
    struct lyd_node *node = NULL;
    return node;
}

static void fuzz_lyd_new_implicit_all(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = create_dummy_tree();
    struct ly_ctx *ctx = create_context();
    struct lyd_node *diff = NULL;
    uint32_t implicit_options = 0;

    if (ctx) {
        lyd_new_implicit_all(&tree, ctx, implicit_options, &diff);
        lyd_free_all(diff);
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_validate_ext(const uint8_t *Data, size_t Size) {
    struct lyd_node *ext_tree = create_dummy_tree();
    struct lysc_ext_instance *ext = NULL;
    struct lyd_node *diff = NULL;
    uint32_t val_opts = 0;

    lyd_validate_ext(&ext_tree, ext, val_opts, &diff);
    lyd_free_all(diff);
}

static void fuzz_lyd_new_path2(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    struct lyd_node *parent = NULL;
    struct lyd_node *new_parent = NULL;
    struct lyd_node *new_node = NULL;
    const char *path = "/dummy/path";
    const void *value = NULL;
    uint64_t value_size_bits = 0;
    uint32_t any_hints = 0;
    uint32_t options = 0;

    if (ctx) {
        lyd_new_path2(parent, ctx, path, value, value_size_bits, any_hints, options, &new_parent, &new_node);
        lyd_free_all(new_parent);
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_validate_all(const uint8_t *Data, size_t Size) {
    struct lyd_node *tree = create_dummy_tree();
    struct ly_ctx *ctx = create_context();
    struct lyd_node *diff = NULL;
    uint32_t val_opts = 0;

    if (ctx) {
        lyd_validate_all(&tree, ctx, val_opts, &diff);
        lyd_free_all(diff);
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_parse_data(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    struct lyd_node *tree = NULL;
    struct ly_in *in = NULL;
    LYD_FORMAT format = 0;
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;

    if (ctx) {
        if (ly_in_new_memory((const char *)Data, &in) == LY_SUCCESS) {
            lyd_parse_data(ctx, NULL, in, format, parse_options, validate_options, &tree);
            lyd_free_all(tree);
            ly_in_free(in, 0);
        }
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_dup_single_to_ctx(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = create_dummy_tree();
    struct ly_ctx *ctx = create_context();
    struct lyd_node *dup = NULL;
    uint32_t options = 0;

    if (ctx) {
        lyd_dup_single_to_ctx(node, ctx, NULL, options, &dup);
        lyd_free_all(dup);
        ly_ctx_destroy(ctx);
    }
}

int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size) {
    fuzz_lyd_new_implicit_all(Data, Size);
    fuzz_lyd_validate_ext(Data, Size);
    fuzz_lyd_new_path2(Data, Size);
    fuzz_lyd_validate_all(Data, Size);
    fuzz_lyd_parse_data(Data, Size);
    fuzz_lyd_dup_single_to_ctx(Data, Size);
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

        LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    