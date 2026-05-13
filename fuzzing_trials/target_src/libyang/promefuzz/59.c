// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_destroy at context.c:1503:1 in context.h
// ly_ctx_new at context.c:278:1 in context.h
// lyd_new_implicit_all at tree_data_new.c:2010:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_validate_ext at validation.c:2148:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_path2 at tree_data_new.c:1787:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_validate_all at validation.c:2202:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_parse_data at tree_data.c:195:1 in parser_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_dup_single_to_ctx at tree_data.c:2522:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parser_data.h"
#include "tree_data.h"
#include "libyang.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure the input data is null-terminated
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) {
        return 0;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    // Prepare dummy file
    prepare_dummy_file(Data, Size);

    // Initialize libyang context
    struct ly_ctx *ctx = NULL;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        free(null_terminated_data);
        return 0;
    }

    // Initialize variables for fuzzing
    struct lyd_node *tree = NULL;
    struct lyd_node *diff = NULL;
    struct lyd_node *ext_tree = NULL;
    struct lysc_ext_instance *ext = NULL;
    struct lyd_node *new_parent = NULL;
    struct lyd_node *new_node = NULL;
    struct lyd_node *dup = NULL;
    struct ly_in *in = NULL;
    LYD_FORMAT format = LYD_JSON;
    uint32_t options = 0;
    LY_ERR ret;

    // Fuzzing lyd_new_implicit_all
    ret = lyd_new_implicit_all(&tree, ctx, options, &diff);
    if (ret != LY_SUCCESS && diff) {
        lyd_free_all(diff);
    }

    // Fuzzing lyd_validate_ext
    ret = lyd_validate_ext(&ext_tree, ext, options, &diff);
    if (ret != LY_SUCCESS && diff) {
        lyd_free_all(diff);
    }

    // Fuzzing lyd_new_path2
    char path[256];
    snprintf(path, sizeof(path), "/dummy-module:%.*s", (int)Size, Data);
    ret = lyd_new_path2(NULL, ctx, path, NULL, 0, 0, options, &new_parent, &new_node);
    if (ret != LY_SUCCESS && new_node) {
        lyd_free_all(new_node);
    }

    // Fuzzing lyd_validate_all
    ret = lyd_validate_all(&tree, ctx, options, &diff);
    if (ret != LY_SUCCESS && diff) {
        lyd_free_all(diff);
    }

    // Fuzzing lyd_parse_data
    if (ly_in_new_memory(null_terminated_data, &in) == LY_SUCCESS) {
        ret = lyd_parse_data(ctx, NULL, in, format, options, options, &tree);
        if (ret != LY_SUCCESS && tree) {
            lyd_free_all(tree);
        }
        ly_in_free(in, 0);
    }

    // Fuzzing lyd_dup_single_to_ctx
    if (new_node) {
        ret = lyd_dup_single_to_ctx(new_node, ctx, NULL, options, &dup);
        if (ret != LY_SUCCESS && dup) {
            lyd_free_all(dup);
        }
    }

    // Cleanup
    if (tree) {
        lyd_free_all(tree);
    }
    ly_ctx_destroy(ctx);
    free(null_terminated_data);

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

        LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    