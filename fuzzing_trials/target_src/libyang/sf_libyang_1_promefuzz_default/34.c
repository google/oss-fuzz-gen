// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_value_fragment at tree_data.c:252:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_op at tree_data.c:352:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_dup_siblings at tree_data.c:2535:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_data_path at tree_data.c:238:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>
#include <parser_data.h>
#include <tree_data.h>

static void fuzz_lyd_parse_op(const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    struct ly_in *in;
    LYD_FORMAT format = LYD_XML;
    enum lyd_type data_type = LYD_TYPE_RPC_NETCONF;
    uint32_t parse_options = 0;
    struct lyd_node *tree = NULL;
    struct lyd_node *op = NULL;
    LY_ERR ret;

    // Ensure the input data is null-terminated
    char *input_data = (char *)malloc(Size + 1);
    memcpy(input_data, Data, Size);
    input_data[Size] = '\0';

    ly_in_new_memory(input_data, &in);

    ret = lyd_parse_op(ctx, parent, in, format, data_type, parse_options, &tree, &op);

    if (ret == LY_SUCCESS) {
        lyd_free_all(tree);
        lyd_free_all(op);
    }

    ly_in_free(in, 0);
    free(input_data);
}

static void fuzz_lyd_dup_siblings(const struct lyd_node *node, const uint8_t *Data, size_t Size) {
    struct lyd_node *parent = NULL;
    uint32_t options = 0;
    struct lyd_node *dup = NULL;
    LY_ERR ret;

    ret = lyd_dup_siblings(node, parent, options, &dup);

    if (ret == LY_SUCCESS) {
        lyd_free_all(dup);
    }
}

static void fuzz_lyd_parse_data_path(const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    const char *path = "./dummy_file";
    FILE *file = fopen(path, "wb");
    if (!file) {
        return;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    LYD_FORMAT format = 0;
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;
    struct lyd_node *tree = NULL;
    LY_ERR ret;

    ret = lyd_parse_data_path(ctx, path, format, parse_options, validate_options, &tree);

    if (ret == LY_SUCCESS) {
        lyd_free_all(tree);
    }
}

static void fuzz_lyd_new_term(struct lyd_node *parent, const struct lys_module *module, const uint8_t *Data, size_t Size) {
    char *value = (char *)malloc(Size + 1);
    memcpy(value, Data, Size);
    value[Size] = '\0';

    const char *name = "test-node";
    uint32_t options = 0;
    struct lyd_node *node = NULL;
    LY_ERR ret;

    ret = lyd_new_term(parent, module, name, value, options, &node);

    if (ret == LY_SUCCESS) {
        lyd_free_all(node);
    }

    free(value);
}

static void fuzz_lyd_new_path(struct lyd_node *parent, const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    const char *path = "/test-path";
    char *value = (char *)malloc(Size + 1);
    memcpy(value, Data, Size);
    value[Size] = '\0';

    uint32_t options = 0;
    struct lyd_node *node = NULL;
    LY_ERR ret;

    ret = lyd_new_path(parent, ctx, path, value, options, &node);

    if (ret == LY_SUCCESS) {
        lyd_free_all(node);
    }

    free(value);
}

static void fuzz_lyd_parse_value_fragment(const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    struct ly_in *in;
    const char *path = "/test-path";
    LYD_FORMAT format = LYD_JSON;
    uint32_t new_val_options = 0;
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;
    struct lyd_node *tree = NULL;
    LY_ERR ret;

    // Ensure the input data is null-terminated
    char *input_data = (char *)malloc(Size + 1);
    memcpy(input_data, Data, Size);
    input_data[Size] = '\0';

    ly_in_new_memory(input_data, &in);

    ret = lyd_parse_value_fragment(ctx, path, in, format, new_val_options, parse_options, validate_options, &tree);

    if (ret == LY_SUCCESS) {
        lyd_free_all(tree);
    }

    ly_in_free(in, 0);
    free(input_data);
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    fuzz_lyd_parse_op(ctx, Data, Size);
    fuzz_lyd_dup_siblings(NULL, Data, Size);
    fuzz_lyd_parse_data_path(ctx, Data, Size);
    fuzz_lyd_new_term(NULL, NULL, Data, Size);
    fuzz_lyd_new_path(NULL, ctx, Data, Size);
    fuzz_lyd_parse_value_fragment(ctx, Data, Size);

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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    