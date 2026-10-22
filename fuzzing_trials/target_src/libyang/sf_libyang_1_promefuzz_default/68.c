// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// lyd_path at tree_data.c:2974:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_value_fragment at tree_data.c:252:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_data_path at tree_data.c:238:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_validate_all at validation.c:2202:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tree_data.h"
#include "parser_data.h"
#include "context.h"
#include "in.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static void destroy_context(struct ly_ctx *ctx) {
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_parse_value_fragment(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct ly_in *in = NULL;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        destroy_context(ctx);
        return;
    }

    struct lyd_node *tree = NULL;
    lyd_parse_value_fragment(ctx, "/example:path", in, LYD_JSON, 0, 0, 0, &tree);

    lyd_free_all(tree);
    ly_in_free(in, 0);
    destroy_context(ctx);
}

static void fuzz_lyd_parse_data_path() {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    FILE *file = fopen("./dummy_file", "w");
    if (!file) {
        destroy_context(ctx);
        return;
    }
    fprintf(file, "{\"example\": \"data\"}");
    fclose(file);

    struct lyd_node *tree = NULL;
    lyd_parse_data_path(ctx, "./dummy_file", LYD_JSON, 0, 0, &tree);

    lyd_free_all(tree);
    destroy_context(ctx);
}

static void fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct lyd_node *tree = NULL;
    // Ensure the data is null-terminated
    char *data_copy = (char *)malloc(Size + 1);
    if (!data_copy) {
        destroy_context(ctx);
        return;
    }
    memcpy(data_copy, Data, Size);
    data_copy[Size] = '\0';

    lyd_parse_data_mem(ctx, data_copy, LYD_JSON, 0, 0, &tree);

    lyd_free_all(tree);
    free(data_copy);
    destroy_context(ctx);
}

static void fuzz_lyd_validate_all() {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct lyd_node *tree = NULL;
    struct lyd_node *diff = NULL;
    lyd_validate_all(&tree, ctx, 0, &diff);

    lyd_free_all(tree);
    lyd_free_all(diff);
    destroy_context(ctx);
}

static void fuzz_lyd_path() {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct lys_module *mod = ly_ctx_get_module_implemented(ctx, "example");
    if (!mod) {
        destroy_context(ctx);
        return;
    }

    struct lysc_node *schema = mod->compiled->data;
    struct lyd_node node = {0};
    node.schema = schema; // Initialize with valid schema
    char *path = lyd_path(&node, 0, NULL, 0);
    free(path);

    destroy_context(ctx);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct lys_module mod = { .ctx = ctx, .name = "example" };
    struct lyd_node *node = NULL;
    // Ensure the data is null-terminated
    char *value_copy = (char *)malloc(Size + 1);
    if (!value_copy) {
        destroy_context(ctx);
        return;
    }
    memcpy(value_copy, Data, Size);
    value_copy[Size] = '\0';

    lyd_new_term(NULL, &mod, "name", value_copy, 0, &node);

    lyd_free_all(node);
    free(value_copy);
    destroy_context(ctx);
}

int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    fuzz_lyd_parse_value_fragment(Data, Size);
    fuzz_lyd_parse_data_path();
    fuzz_lyd_parse_data_mem(Data, Size);
    fuzz_lyd_validate_all();
    fuzz_lyd_path();
    fuzz_lyd_new_term(Data, Size);
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

        LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    