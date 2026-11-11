// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_parse_op at tree_data.c:352:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_op at tree_data.c:352:1 in parser_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang.h>
#include "parser_data.h"
#include "tree_data.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static struct ly_in *create_input(const uint8_t *Data, size_t Size) {
    struct ly_in *in;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        return NULL;
    }
    return in;
}

static void cleanup(struct ly_ctx *ctx, struct ly_in *in, struct lyd_node *tree, struct lyd_node *op) {
    lyd_free_all(tree);
    lyd_free_all(op);
    ly_in_free(in, 0);
    ly_ctx_destroy(ctx);
}

int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return 0;
    }

    struct ly_in *in = create_input(Data, Size);
    if (!in) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *tree = NULL;
    struct lyd_node *op = NULL;

    // Ensure the input is null-terminated to prevent overflow
    char *null_terminated_input = (char *)malloc(Size + 1);
    if (!null_terminated_input) {
        cleanup(ctx, in, tree, op);
        return 0;
    }
    memcpy(null_terminated_input, Data, Size);
    null_terminated_input[Size] = '\0';

    ly_in_free(in, 0);
    if (ly_in_new_memory(null_terminated_input, &in) != LY_SUCCESS) {
        free(null_terminated_input);
        cleanup(ctx, NULL, tree, op);
        return 0;
    }

    LY_ERR ret = lyd_parse_op(ctx, NULL, in, LYD_XML, LYD_TYPE_RPC_NETCONF, 0, &tree, &op);
    if (ret != LY_SUCCESS && ret != LY_ENOT) {
        cleanup(ctx, in, tree, op);
        free(null_terminated_input);
        return 0;
    }

    // Try different data types and formats
    lyd_free_all(tree);
    lyd_free_all(op);
    tree = NULL;
    op = NULL;

    ret = lyd_parse_op(ctx, NULL, in, LYD_JSON, LYD_TYPE_NOTIF_RESTCONF, 0, &tree, &op);
    if (ret != LY_SUCCESS && ret != LY_ENOT) {
        cleanup(ctx, in, tree, op);
        free(null_terminated_input);
        return 0;
    }

    cleanup(ctx, in, tree, op);
    free(null_terminated_input);
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

        LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    