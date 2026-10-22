// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_path at tree_data.c:2974:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"
#include "tree_data.h"
#include "parser_data.h"

static struct ly_ctx *initialize_context() {
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

static struct ly_in *initialize_input(const uint8_t *Data, size_t Size) {
    struct ly_in *in = NULL;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        return NULL;
    }
    return in;
}

static void cleanup_input(struct ly_in *in) {
    if (in) {
        ly_in_free(in, 0);
    }
}

int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    struct ly_ctx *ctx = initialize_context();
    if (!ctx) return 0;

    struct ly_in *in = initialize_input(Data, Size);
    if (!in) {
        cleanup_context(ctx);
        return 0;
    }

    struct lyd_node *tree = NULL;
    const char *path = "/example-module:container";
    LYD_FORMAT format = LYD_JSON;
    uint32_t new_val_options = 0;
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;

    // Ensure data is null-terminated for safe string operations
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) {
        cleanup_input(in);
        cleanup_context(ctx);
        return 0;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    lyd_parse_value_fragment(ctx, path, in, format, new_val_options, parse_options, validate_options, &tree);

    char file_path[] = "./dummy_file";
    FILE *file = fopen(file_path, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        lyd_parse_data_path(ctx, file_path, 0, parse_options, validate_options, &tree);
    }

    lyd_parse_data_mem(ctx, null_terminated_data, format, parse_options, validate_options, &tree);

    lyd_validate_all(&tree, ctx, validate_options, NULL);

    if (tree) {
        char *path_str = lyd_path(tree, 0, NULL, 0);
        if (path_str) {
            free(path_str);
        }
        lyd_free_all(tree);
    }

    free(null_terminated_data);
    cleanup_input(in);
    cleanup_context(ctx);

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

        LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    