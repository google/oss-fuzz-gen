// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_path at tree_data.c:2974:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "libyang.h"
#include "tree_data.h"
#include "parser_data.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static struct ly_in *create_input(const uint8_t *Data, size_t Size) {
    struct ly_in *in = NULL;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        return NULL;
    }
    return in;
}

int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
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

    // Fuzzing lyd_parse_value_fragment
    {
        struct lyd_node *tree = NULL;
        char path[] = "/example-module:container";
        LY_ERR ret = lyd_parse_value_fragment(ctx, path, in, LYD_JSON, 0, 0, 0, &tree);
        if (ret == LY_SUCCESS) {
            lyd_free_all(tree);
        }
    }

    // Fuzzing lyd_parse_data_path
    {
        struct lyd_node *tree = NULL;
        const char *filepath = "./dummy_file";
        FILE *f = fopen(filepath, "wb");
        if (f) {
            fwrite(Data, 1, Size, f);
            fclose(f);
            LY_ERR ret = lyd_parse_data_path(ctx, filepath, LYD_JSON, 0, 0, &tree);
            if (ret == LY_SUCCESS) {
                lyd_free_all(tree);
            }
            unlink(filepath);
        }
    }

    // Fuzzing lyd_parse_data_mem
    {
        struct lyd_node *tree = NULL;
        char *data = strndup((const char *)Data, Size);
        if (data) {
            LY_ERR ret = lyd_parse_data_mem(ctx, data, LYD_JSON, 0, 0, &tree);
            if (ret == LY_SUCCESS) {
                lyd_free_all(tree);
            }
            free(data);
        }
    }

    // Fuzzing lyd_new_path
    {
        struct lyd_node *node = NULL;
        char path[] = "/example-module:container";
        char value[] = "value";
        LY_ERR ret = lyd_new_path(NULL, ctx, path, value, 0, &node);
        if (ret == LY_SUCCESS) {
            lyd_free_all(node);
        }
    }

    // Fuzzing lyd_path
    {
        struct lyd_node *node = NULL;
        char path[] = "/example-module:container";
        char value[] = "value";
        if (lyd_new_path(NULL, ctx, path, value, 0, &node) == LY_SUCCESS) {
            char *node_path = lyd_path(node, LYD_PATH_STD, NULL, 0);
            if (node_path) {
                free(node_path);
            }
            lyd_free_all(node);
        }
    }

    // Fuzzing lyd_new_term
    {
        struct lyd_node *node = NULL;
        char name[] = "leaf";
        char value[] = "value";
        LY_ERR ret = lyd_new_term(NULL, NULL, name, value, 0, &node);
        if (ret == LY_SUCCESS) {
            lyd_free_all(node);
        }
    }

    ly_in_free(in, 0);
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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    