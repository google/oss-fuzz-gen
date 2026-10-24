// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_value_fragment at tree_data.c:252:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_op at tree_data.c:352:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_data_path at tree_data.c:238:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libyang.h>
#include <parser_data.h>
#include <tree_data.h>

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static void cleanup_context(struct ly_ctx *ctx) {
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
}

static void fuzz_lyd_parse_op(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct ly_in *in = NULL;
    char *data_copy = NULL;

    if (Size > 0) {
        data_copy = (char *)malloc(Size + 1);
        if (!data_copy) {
            cleanup_context(ctx);
            return;
        }
        memcpy(data_copy, Data, Size);
        data_copy[Size] = '\0';

        if (ly_in_new_memory(data_copy, &in) != LY_SUCCESS) {
            free(data_copy);
            cleanup_context(ctx);
            return;
        }
    }

    enum lyd_type data_type = LYD_TYPE_RPC_NETCONF;
    LYD_FORMAT format = LYD_XML;
    uint32_t parse_options = 0;
    struct lyd_node *tree = NULL;
    struct lyd_node *op = NULL;

    lyd_parse_op(ctx, NULL, in, format, data_type, parse_options, &tree, &op);

    lyd_free_all(tree);
    lyd_free_all(op);
    ly_in_free(in, 0);
    free(data_copy);
    cleanup_context(ctx);
}

static void fuzz_lyd_dup_siblings(const uint8_t *Data, size_t Size) {
    struct lyd_node *node = NULL;
    struct lyd_node *dup = NULL;

    lyd_dup_siblings(node, NULL, 0, &dup);

    lyd_free_all(dup);
}

static void fuzz_lyd_parse_data_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        cleanup_context(ctx);
        return;
    }

    fwrite(Data, 1, Size, file);
    fclose(file);

    struct lyd_node *tree = NULL;
    lyd_parse_data_path(ctx, "./dummy_file", LYD_XML, 0, 0, &tree);

    lyd_free_all(tree);
    cleanup_context(ctx);
}

static void fuzz_lyd_new_term(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct lys_module *module = ly_ctx_get_module_implemented(ctx, "dummy-module");
    if (!module) {
        cleanup_context(ctx);
        return;
    }

    char *value = (char *)malloc(Size + 1);
    if (!value) {
        cleanup_context(ctx);
        return;
    }

    memcpy(value, Data, Size);
    value[Size] = '\0';

    struct lyd_node *node = NULL;
    lyd_new_term(NULL, module, "dummy-name", value, 0, &node);

    lyd_free_all(node);
    free(value);
    cleanup_context(ctx);
}

static void fuzz_lyd_new_path(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    char *path = (char *)malloc(Size + 1);
    if (!path) {
        cleanup_context(ctx);
        return;
    }

    memcpy(path, Data, Size);
    path[Size] = '\0';

    struct lyd_node *node = NULL;
    lyd_new_path(NULL, ctx, path, NULL, 0, &node);

    lyd_free_all(node);
    free(path);
    cleanup_context(ctx);
}

static void fuzz_lyd_parse_value_fragment(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = create_context();
    if (!ctx) return;

    struct ly_in *in = NULL;
    char *data_copy = (char *)malloc(Size + 1);
    if (!data_copy) {
        cleanup_context(ctx);
        return;
    }

    memcpy(data_copy, Data, Size);
    data_copy[Size] = '\0';

    if (ly_in_new_memory(data_copy, &in) != LY_SUCCESS) {
        free(data_copy);
        cleanup_context(ctx);
        return;
    }

    struct lyd_node *tree = NULL;
    lyd_parse_value_fragment(ctx, "/dummy-path", in, LYD_JSON, 0, 0, 0, &tree);

    lyd_free_all(tree);
    ly_in_free(in, 0);
    free(data_copy);
    cleanup_context(ctx);
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    fuzz_lyd_parse_op(Data, Size);
    fuzz_lyd_dup_siblings(Data, Size);
    fuzz_lyd_parse_data_path(Data, Size);
    fuzz_lyd_new_term(Data, Size);
    fuzz_lyd_new_path(Data, Size);
    fuzz_lyd_parse_value_fragment(Data, Size);
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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    