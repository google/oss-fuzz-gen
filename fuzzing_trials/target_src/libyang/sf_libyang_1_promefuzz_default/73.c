// This fuzz driver is generated for library libyang, aiming to fuzz the following functions:
// ly_ctx_new at context.c:278:1 in context.h
// ly_ctx_destroy at context.c:1503:1 in context.h
// lyd_free_all at tree_data_free.c:311:1 in tree_data.h
// lyd_new_path at tree_data_new.c:1777:1 in tree_data.h
// lyd_path at tree_data.c:2974:1 in tree_data.h
// lyd_new_term at tree_data_new.c:742:1 in tree_data.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libyang.h"
#include "tree_data.h"
#include "parser_data.h"

#define DUMMY_FILE_PATH "./dummy_file"

static struct ly_ctx *create_dummy_context() {
    struct ly_ctx *ctx;
    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        return NULL;
    }
    return ctx;
}

static struct ly_in *create_dummy_input_handler(const uint8_t *Data, size_t Size) {
    struct ly_in *in;
    if (ly_in_new_memory((const char *)Data, &in) != LY_SUCCESS) {
        return NULL;
    }
    return in;
}

static void cleanup(struct ly_ctx *ctx, struct ly_in *in, struct lyd_node *tree) {
    if (ctx) {
        ly_ctx_destroy(ctx);
    }
    if (in) {
        ly_in_free(in, 0);
    }
    if (tree) {
        lyd_free_all(tree);
    }
}

int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    struct ly_ctx *ctx = create_dummy_context();
    struct ly_in *in = create_dummy_input_handler(Data, Size);
    struct lyd_node *tree = NULL;

    if (!ctx || !in) {
        cleanup(ctx, in, tree);
        return 0;
    }

    // Fuzzing lyd_parse_value_fragment
    const char *path = "/dummy:path";
    LYD_FORMAT format = LYD_JSON;
    uint32_t new_val_options = 0;
    uint32_t parse_options = 0;
    uint32_t validate_options = 0;

    lyd_parse_value_fragment(ctx, path, in, format, new_val_options, parse_options, validate_options, &tree);

    // Fuzzing lyd_parse_data_path
    FILE *dummy_file = fopen(DUMMY_FILE_PATH, "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);

        lyd_parse_data_path(ctx, DUMMY_FILE_PATH, format, parse_options, validate_options, &tree);
    }

    // Ensure data is null-terminated for lyd_parse_data_mem
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (null_terminated_data) {
        memcpy(null_terminated_data, Data, Size);
        null_terminated_data[Size] = '\0';
        lyd_parse_data_mem(ctx, null_terminated_data, format, parse_options, validate_options, &tree);
        free(null_terminated_data);
    }

    // Fuzzing lyd_new_path
    const char *node_path = "/dummy:node";
    const char *value = "dummy_value";
    uint32_t options = 0;
    struct lyd_node *new_node = NULL;

    lyd_new_path(NULL, ctx, node_path, value, options, &new_node);

    // Fuzzing lyd_path
    char buffer[256];
    lyd_path(new_node, 0, buffer, sizeof(buffer));

    // Fuzzing lyd_new_term
    struct lys_module dummy_module = {0};
    dummy_module.name = "dummy_module";
    lyd_new_term(NULL, &dummy_module, "dummy_name", "dummy_value", options, &new_node);

    cleanup(ctx, in, tree);
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

        LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    