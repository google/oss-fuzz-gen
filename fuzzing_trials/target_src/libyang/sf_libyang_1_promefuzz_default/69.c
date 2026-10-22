// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_path at tree_data.c:2974:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_tree at tree_data_free.c:265:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"
#include "tree_data.h"
#include "parser_data.h"

static void fuzz_lyd_parse_value_fragment(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    struct ly_in *in = NULL;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return;
    }

    struct lyd_node *tree = NULL;
    const char *path = "/example:node";
    LY_ERR ret = lyd_parse_value_fragment(ctx, path, in, LYD_JSON, 0, 0, 0, &tree);

    lyd_free_all(tree);
    ly_in_free(in, 0);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_parse_data_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    FILE *file = fopen("./dummy_file", "w");
    if (!file) {
        ly_ctx_destroy(ctx);
        return;
    }

    fwrite(Data, 1, Size, file);
    fclose(file);

    struct lyd_node *tree = NULL;
    LY_ERR ret = lyd_parse_data_path(ctx, "./dummy_file", LYD_JSON, 0, 0, &tree);

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    struct lyd_node *tree = NULL;
    char *data = (char *)malloc(Size + 1);
    if (!data) {
        ly_ctx_destroy(ctx);
        return;
    }

    memcpy(data, Data, Size);
    data[Size] = '\0';

    LY_ERR ret = lyd_parse_data_mem(ctx, data, LYD_JSON, 0, 0, &tree);

    free(data);
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    struct lyd_node *node = NULL;
    const char *path = "/example:node";
    char *value = (char *)malloc(Size + 1);
    if (!value) {
        ly_ctx_destroy(ctx);
        return;
    }

    memcpy(value, Data, Size);
    value[Size] = '\0';

    LY_ERR ret = lyd_new_path(NULL, ctx, path, value, 0, &node);

    free(value);
    lyd_free_tree(node);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_path(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct lyd_node)) {
        return;
    }

    struct lyd_node *node = (struct lyd_node *)Data;
    if (node->parent == node) {
        return;
    }

    char buffer[256];
    char *path = lyd_path(node, 0, buffer, sizeof(buffer));

    if (path && path != buffer) {
        free(path);
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    const struct lys_module *module = ly_ctx_get_module_implemented(ctx, "example");
    if (!module) {
        ly_ctx_destroy(ctx);
        return;
    }

    struct lyd_node *node = NULL;
    char *value = (char *)malloc(Size + 1);
    if (!value) {
        ly_ctx_destroy(ctx);
        return;
    }

    memcpy(value, Data, Size);
    value[Size] = '\0';

    LY_ERR ret = lyd_new_term(NULL, module, "leaf", value, 0, &node);

    free(value);
    lyd_free_tree(node);
    ly_ctx_destroy(ctx);
}

int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size) {
    fuzz_lyd_parse_value_fragment(Data, Size);
    fuzz_lyd_parse_data_path(Data, Size);
    fuzz_lyd_parse_data_mem(Data, Size);
    fuzz_lyd_new_path(Data, Size);
    fuzz_lyd_path(Data, Size);
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

        LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    