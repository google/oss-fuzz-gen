// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_path at tree_data.c:2974:1 in tree_data.h
// ly_ctx_get_module_implemented at context.c:1009:1 in context.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// ly_ctx_destroy at context.c:1503:1 in context.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"

static struct ly_ctx *create_context() {
    struct ly_ctx *ctx;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static char *create_temp_file(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return NULL;
    }
    fwrite(data, 1, size, file);
    fclose(file);
    return "./dummy_file";
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = create_context();
    if (!ctx) {
        return 0;
    }

    struct ly_in *in;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        ly_ctx_destroy(ctx);
        return 0;
    }

    struct lyd_node *tree = NULL;
    const char *path = "/example-module:container";
    LY_ERR ret = lyd_parse_value_fragment(ctx, path, in, LYD_JSON, 0, 0, 0, &tree);

    if (ret == LY_SUCCESS) {
        lyd_free_all(tree);
    }

    char *temp_file = create_temp_file(Data, Size);
    if (temp_file) {
        ret = lyd_parse_data_path(ctx, temp_file, 0, 0, 0, &tree);
        if (ret == LY_SUCCESS) {
            lyd_free_all(tree);
        }
    }

    // Ensure the data is null-terminated for lyd_parse_data_mem
    char *data_mem = (char *)malloc(Size + 1);
    if (data_mem) {
        memcpy(data_mem, Data, Size);
        data_mem[Size] = '\0';

        ret = lyd_parse_data_mem(ctx, data_mem, LYD_JSON, 0, 0, &tree);
        if (ret == LY_SUCCESS) {
            lyd_free_all(tree);
        }

        free(data_mem);
    }

    struct lyd_node *diff = NULL;
    ret = lyd_validate_all(&tree, ctx, 0, &diff);
    if (ret == LY_SUCCESS) {
        lyd_free_all(diff);
    }

    char buffer[256];
    char *path_result = lyd_path(tree, 0, buffer, sizeof(buffer));
    if (path_result && path_result != buffer) {
        free(path_result);
    }

    const struct lys_module *module = ly_ctx_get_module_implemented(ctx, "example-module");
    if (module) {
        ret = lyd_new_term(NULL, module, "leaf", (const char *)Data, 0, &tree);
        if (ret == LY_SUCCESS) {
            lyd_free_all(tree);
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

        LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    