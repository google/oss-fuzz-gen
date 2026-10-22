// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_value_fragment at tree_data.c:252:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_data_path at tree_data.c:238:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_data_mem at tree_data.c:210:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_path at tree_data.c:2974:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tree_data.h"
#include "parser_data.h"
#include "context.h"
#include "in.h"

static void fuzz_lyd_parse_value_fragment(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    struct ly_in *in = NULL;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return;
    }

    struct lyd_node *tree = NULL;
    lyd_parse_value_fragment(ctx, "/example:path", in, LYD_JSON, 0, 0, 0, &tree);

    lyd_free_all(tree);
    ly_in_free(in, 0);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_parse_data_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        ly_ctx_destroy(ctx);
        return;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    struct lyd_node *tree = NULL;
    lyd_parse_data_path(ctx, "./dummy_file", LYD_JSON, 0, 0, &tree);

    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_parse_data_mem(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    // Ensure null-terminated input
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) {
        ly_ctx_destroy(ctx);
        return;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    struct lyd_node *tree = NULL;
    lyd_parse_data_mem(ctx, null_terminated_data, LYD_JSON, 0, 0, &tree);

    lyd_free_all(tree);
    free(null_terminated_data);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    // Ensure null-terminated input
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) {
        ly_ctx_destroy(ctx);
        return;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    struct lyd_node *node = NULL;
    lyd_new_path(NULL, ctx, "/example:path", null_terminated_data, 0, &node);

    lyd_free_all(node);
    free(null_terminated_data);
    ly_ctx_destroy(ctx);
}

static void fuzz_lyd_path(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;
    char *buffer = NULL;

    if (Size >= sizeof(struct lyd_node)) {
        node = (struct lyd_node *)Data;
        buffer = lyd_path(node, 0, NULL, 0);
        free(buffer);
    }
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) return;

    const struct lys_module *module = ly_ctx_get_module_implemented(ctx, "example");
    struct lyd_node *node = NULL;

    // Ensure null-terminated input if Size > 0
    char *value = NULL;
    if (Size > 0) {
        value = (char *)malloc(Size + 1);
        if (!value) {
            ly_ctx_destroy(ctx);
            return;
        }
        memcpy(value, Data, Size);
        value[Size] = '\0';
    }

    lyd_new_term(NULL, module, "leaf", value, 0, &node);

    lyd_free_all(node);
    free(value);
    ly_ctx_destroy(ctx);
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
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

        LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    